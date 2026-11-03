//! Canonical JSON encoding and SHA-256 for audited argument payloads.

use sha2::{Digest, Sha256};

/// SHA-256 of the canonical JSON encoding of a tool-argument payload, hex.
///
/// The audit never stores arguments (they can hold secrets); the hashes let a
/// reader tie the requested and the executed call to the same decision row
/// without leaking either payload.
pub(super) fn arguments_sha256(arguments: &serde_json::Value) -> String {
    let mut encoded = String::new();
    append_canonical_json(arguments, &mut encoded);
    let digest = Sha256::digest(&encoded);
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Append a deterministic JSON encoding: object keys are sorted at every
/// depth, and numbers use normalized scientific notation. The latter makes
/// equivalent JSON spellings such as `1.0`, `1e0`, and `10e-1` hash alike,
/// despite `arbitrary_precision` retaining the source number lexeme.
fn append_canonical_json(value: &serde_json::Value, output: &mut String) {
    match value {
        serde_json::Value::Null => output.push_str("null"),
        serde_json::Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        serde_json::Value::Number(number) => {
            output.push_str(&canonical_number(&number.to_string()))
        }
        serde_json::Value::String(value) => output.push_str(
            &serde_json::to_string(value).expect("serializing a JSON string cannot fail"),
        ),
        serde_json::Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                append_canonical_json(value, output);
            }
            output.push(']');
        }
        serde_json::Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_unstable_by_key(|(key, _)| *key);
            output.push('{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).expect("serializing a JSON key cannot fail"),
                );
                output.push(':');
                append_canonical_json(value, output);
            }
            output.push('}');
        }
    }
}

/// Normalize one JSON number into a signed coefficient and a base-ten
/// exponent. The exponent arithmetic is decimal-string based so very large
/// valid JSON exponents remain deterministic without overflow.
fn canonical_number(raw: &str) -> String {
    let (negative, unsigned) = raw
        .strip_prefix('-')
        .map_or((false, raw), |unsigned| (true, unsigned));
    let exponent_at = unsigned.find(['e', 'E']);
    let (mantissa, exponent) = exponent_at
        .map(|index| (&unsigned[..index], &unsigned[index + 1..]))
        .unwrap_or((unsigned, "0"));
    let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits = String::with_capacity(integer.len() + fraction.len());
    digits.push_str(integer);
    digits.push_str(fraction);
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return "0".to_string();
    }
    let trailing_zeroes = significant.len() - significant.trim_end_matches('0').len();
    let coefficient = &significant[..significant.len() - trailing_zeroes];
    let adjustment = i64::try_from(trailing_zeroes).expect("number length fits in i64")
        + i64::try_from(coefficient.len() - 1).expect("number length fits in i64")
        - i64::try_from(fraction.len()).expect("number length fits in i64");
    let exponent = add_decimal_integer(exponent, adjustment);
    let mut output = String::with_capacity(coefficient.len() + exponent.len() + 4);
    if negative {
        output.push('-');
    }
    output.push(coefficient.as_bytes()[0] as char);
    if coefficient.len() > 1 {
        output.push('.');
        output.push_str(&coefficient[1..]);
    }
    output.push('e');
    output.push_str(&exponent);
    output
}

fn add_decimal_integer(value: &str, adjustment: i64) -> String {
    let (value_negative, value_digits) = normalized_signed_digits(value);
    let adjustment = adjustment.to_string();
    let (adjustment_negative, adjustment_digits) = normalized_signed_digits(&adjustment);
    let value_is_zero = value_digits == "0";
    let adjustment_is_zero = adjustment_digits == "0";
    if value_is_zero {
        return signed_digits(adjustment_negative, &adjustment_digits);
    }
    if adjustment_is_zero {
        return signed_digits(value_negative, &value_digits);
    }
    if value_negative == adjustment_negative {
        return signed_digits(
            value_negative,
            &add_magnitudes(&value_digits, &adjustment_digits),
        );
    }
    match compare_magnitudes(&value_digits, &adjustment_digits) {
        std::cmp::Ordering::Greater => signed_digits(
            value_negative,
            &subtract_magnitudes(&value_digits, &adjustment_digits),
        ),
        std::cmp::Ordering::Less => signed_digits(
            adjustment_negative,
            &subtract_magnitudes(&adjustment_digits, &value_digits),
        ),
        std::cmp::Ordering::Equal => "0".to_string(),
    }
}

fn normalized_signed_digits(value: &str) -> (bool, String) {
    let (negative, digits) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        (false, "0".to_string())
    } else {
        (negative, digits.to_string())
    }
}

fn signed_digits(negative: bool, digits: &str) -> String {
    if negative && digits != "0" {
        format!("-{digits}")
    } else {
        digits.to_string()
    }
}

fn compare_magnitudes(left: &str, right: &str) -> std::cmp::Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn add_magnitudes(left: &str, right: &str) -> String {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut digits = Vec::with_capacity(left.len().max(right.len()) + 1);
    let mut carry = 0u8;
    for index in 0..left.len().max(right.len()) {
        let a = left
            .get(left.len().wrapping_sub(index + 1))
            .map_or(0, |digit| digit - b'0');
        let b = right
            .get(right.len().wrapping_sub(index + 1))
            .map_or(0, |digit| digit - b'0');
        let sum = a + b + carry;
        digits.push(b'0' + sum % 10);
        carry = sum / 10;
    }
    if carry != 0 {
        digits.push(b'0' + carry);
    }
    digits.reverse();
    String::from_utf8(digits).expect("decimal digits are valid UTF-8")
}

/// Subtract decimal magnitudes where `left >= right`.
fn subtract_magnitudes(left: &str, right: &str) -> String {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut digits = Vec::with_capacity(left.len());
    let mut borrow = 0i16;
    for index in 0..left.len() {
        let a = i16::from(left[left.len() - index - 1] - b'0') - borrow;
        let b = right
            .get(right.len().wrapping_sub(index + 1))
            .map_or(0, |digit| i16::from(digit - b'0'));
        if a < b {
            digits.push((a + 10 - b) as u8 + b'0');
            borrow = 1;
        } else {
            digits.push((a - b) as u8 + b'0');
            borrow = 0;
        }
    }
    while digits.len() > 1 && digits.last() == Some(&b'0') {
        digits.pop();
    }
    digits.reverse();
    String::from_utf8(digits).expect("decimal digits are valid UTF-8")
}
