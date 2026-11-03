//! The joined views of a call's arguments: the leaf order, and the digits-and-letters
//! view that puts a split identifier back together.

use serde_json::Value;

use super::shapes::is_uuid_or_sha;

/// The digits-and-letters view: each leaf that is mostly digits or shaped like
/// an IBAN, reduced to its ASCII letters and digits and joined with no
/// separator. Every other leaf is skipped, so unrelated text between the fields
/// of a split identifier does not break it.
///
/// A whole opaque ID (a UUID, a git SHA or a SHA-256/512 digest) is left out: it
/// is not a piece of a split identifier, and its hex letters would glue to a
/// neighbour's digits into a false IBAN shape.
///
/// Known residual, kept on purpose: the join has no separator, so an epoch next
/// to a small number (`ts: 1700000000` beside `n: 12`) reads as the 12-digit run
/// `170000000012`, which opens with `1` and is a phone candidate. The epoch rule
/// only sees a whole leaf, and a false ask is the cheaper error here.
pub(super) fn digits_and_letters(leaves: &[String]) -> String {
    leaves
        .iter()
        .filter(|leaf| !is_uuid_or_sha(leaf))
        .filter(|leaf| mostly_digits(leaf) || iban_shaped(leaf))
        .flat_map(|leaf| leaf.chars().filter(char::is_ascii_alphanumeric))
        .collect()
}

/// Whether a leaf holds more digits than other non-space characters.
fn mostly_digits(leaf: &str) -> bool {
    let (digits, others) = leaf.chars().filter(|ch| !ch.is_whitespace()).fold(
        (0usize, 0usize),
        |(digits, others), ch| {
            if ch.is_ascii_digit() {
                (digits + 1, others)
            } else {
                (digits, others + 1)
            }
        },
    );
    digits > 0 && digits > others
}

/// Whether a leaf is shaped like the opening of an IBAN: two letters, then two
/// check digits. A two-letter leaf on its own, a split country code, counts too.
fn iban_shaped(leaf: &str) -> bool {
    let bytes = leaf.as_bytes();
    if !(2..=34).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    match bytes {
        [country, code] => country.is_ascii_alphabetic() && code.is_ascii_alphabetic(),
        [country, code, check, digit, ..] => {
            country.is_ascii_alphabetic()
                && code.is_ascii_alphabetic()
                && check.is_ascii_digit()
                && digit.is_ascii_digit()
        }
        _ => false,
    }
}

/// Every string, object key and number in `value` as text, in document order.
/// `leaves` gets all of them; `values` gets only the string and number values,
/// which the reconstructed view joins.
pub(super) fn collect_leaves(value: &Value, leaves: &mut Vec<String>, values: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            leaves.push(text.clone());
            values.push(text.clone());
        }
        Value::Number(number) => {
            leaves.push(number.to_string());
            values.push(number.to_string());
        }
        Value::Array(items) => items
            .iter()
            .for_each(|item| collect_leaves(item, leaves, values)),
        Value::Object(map) => map.iter().for_each(|(key, item)| {
            leaves.push(key.clone());
            collect_leaves(item, leaves, values);
        }),
        Value::Null | Value::Bool(_) => {}
    }
}
