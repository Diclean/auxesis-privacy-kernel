//! Value-shape gates: decides whether the value under a secret-looking
//! name is opaque enough to redact, so ordinary prose stays readable.

use super::*;

/// Bytes an opaque token value may contain.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_' | b'.' | b'+' | b'/' | b'=' | b':' | b'@' | b'~'
        )
}

/// Bytes that end an unquoted value.
pub(super) fn is_value_delim(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            ',' | ';' | '"' | '\'' | ']' | '}' | ')' | '(' | '&' | '|' | '`' | '<' | '>'
        )
}

/// Conservative "this is an opaque token, not an English word or code"
/// test. Catches every 16–31 byte opaque run with a digit or
/// punctuation, every run of ≥6 distinct bytes, and everything ≥32 bytes.
pub(super) fn looks_like_secret(value: &str) -> bool {
    if value.starts_with("eyJ") && value.len() >= 12 {
        return true;
    }
    let len = value.len();
    if len < 16 {
        return false;
    }
    if len >= 32 {
        return true;
    }
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    let mut non_alpha = false;
    for byte in value.bytes() {
        if !byte.is_ascii_alphanumeric() {
            non_alpha = true;
        }
        if !seen[byte as usize] {
            seen[byte as usize] = true;
            distinct += 1;
        }
    }
    non_alpha || distinct >= 6
}

/// Loose value gate for the strongest names: any token-shaped value of at
/// least six bytes that carries a digit, is all-caps/digit, has punctuation,
/// or is long enough to be random. Keeps `short`, `None`, `required` and
/// `parse(input)` readable.
///
/// The digit disjunct is tight: an all-digit value of ten bytes or more
/// is a numeric id or an epoch (`token: 1699999999999`), and a
/// CamelCase identifier (`password: MySecretValue123`, a type name) is not
/// key material by shape alone.
fn plausible_token(value: &str) -> bool {
    if value.len() < 6 || !value.bytes().all(is_token_byte) {
        return false;
    }
    if value.len() >= 10 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if is_camel_identifier(value) {
        return false;
    }
    if looks_like_secret(value) {
        return true;
    }
    let mut digit = false;
    let mut upper = false;
    let mut lower = false;
    let mut non_alnum = false;
    for byte in value.bytes() {
        if byte.is_ascii_digit() {
            digit = true;
        } else if byte.is_ascii_uppercase() {
            upper = true;
        } else if byte.is_ascii_lowercase() {
            lower = true;
        } else {
            non_alnum = true;
        }
    }
    digit || (upper && !lower && value.len() >= 8) || (!lower && non_alnum) || value.len() >= 16
}

/// Is this value shaped like a CamelCase identifier — a type name, an enum
/// variant, a function name — rather than an opaque credential?
///
/// Requires at least three words (`MySecretValue123`), every word starting
/// uppercase with a lowercase tail; all-caps (`CANARYE2ECAMEL18`) and
/// lowercase (`hunter2swordfish`) values are never identifiers, so the
/// shipped canaries stay redacted.
fn is_camel_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_uppercase() {
        return false;
    }
    let mut humps = 0usize;
    let mut word_has_lower = false;
    for (index, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_uppercase() {
            if index > 0 && bytes[index - 1].is_ascii_lowercase() {
                humps += 1;
            }
            word_has_lower = false;
        } else if byte.is_ascii_lowercase() {
            word_has_lower = true;
        } else if byte.is_ascii_digit() {
            // digits attach to the current word
        } else {
            return false;
        }
    }
    humps >= 2 && word_has_lower
}

/// Does a `scheme://…` or `scheme%3A%2F%2F…` value carry userinfo
/// credentials? Only the authority (up to `/`, `?`, `#`, whitespace or a
/// quote) is considered.
fn url_has_userinfo(value: &str) -> bool {
    let Some(authority_start) = url_authority_start(value) else {
        return false;
    };
    let authority = &value[authority_start..];
    let end = authority
        .find(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | '<' | '>'))
        .unwrap_or(authority.len());
    authority[..end].contains('@')
}

/// Start of the authority of a URL value: after `://`, or after a
/// percent-encoded `%3A%2F%2F` scheme separator. Case-insensitive.
fn url_authority_start(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"://") {
            return Some(i + 3);
        }
        if is_percent_scheme_separator(bytes, i) {
            return Some(i + 9);
        }
        i += 1;
    }
    None
}

/// True when `bytes[p..]` starts with `%3A%2F%2F`, ASCII case-insensitive.
pub(super) fn is_percent_scheme_separator(bytes: &[u8], p: usize) -> bool {
    const ENCODED: &[u8] = b"%3A%2F%2F";
    bytes.len() >= p + ENCODED.len() && bytes[p..p + ENCODED.len()].eq_ignore_ascii_case(ENCODED)
}

/// Does `value` carry a percent-encoded URL scheme (`scheme%3A%2F%2F…`)?
fn has_percent_scheme(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut p = 0usize;
    while p + 9 <= bytes.len() {
        if !is_percent_scheme_separator(bytes, p) {
            p += 1;
            continue;
        }
        // The run before the separator must itself be a scheme; walking back
        // over scheme bytes is linear overall because `%` ends every run.
        let mut start = p;
        while start > 0 && is_scheme_byte(bytes[start - 1]) {
            start -= 1;
        }
        if start < p && is_scheme(&value[start..p]) {
            return true;
        }
        p += 9;
    }
    false
}

/// One byte of a URL scheme (`http`, `mongodb+srv`, …).
fn is_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

/// Decide whether the value of a secret-named assignment is a secret.
pub(super) fn value_is_secret(info: NameInfo, value: &str, quoted: bool) -> bool {
    if value.is_empty() {
        return false;
    }
    if info.url_like {
        if url_has_userinfo(value) {
            return true;
        }
        let looks_like_url = value.contains("://") || has_percent_scheme(value);
        if info.webhook && looks_like_url {
            return true;
        }
        if looks_like_url {
            // A credential-free URL stays readable.
            return false;
        }
    }
    if info.aux_key {
        return true;
    }
    if quoted {
        if value.len() < 6 {
            return false;
        }
        if value.chars().any(char::is_whitespace) || value.bytes().any(|byte| !is_token_byte(byte))
        {
            // A quoted passphrase or a value carrying punctuation.
            return true;
        }
    }
    match info.strength {
        Strength::Strong => plausible_token(value),
        Strength::Weak => looks_like_secret(value),
        Strength::None => false,
    }
}

/// A numeric JSON value under a strong secret name is key material
/// once it is long enough to be one (the reported shape was an 18-digit
/// `api_key`). Short numbers — ports, counters, epochs — stay readable, and
/// the text tokenizer keeps its own rule for `token: 1699999999999`.
pub(super) fn numeric_secret(info: NameInfo, text: &str) -> bool {
    info.strength == Strength::Strong && text.bytes().filter(u8::is_ascii_digit).count() >= 16
}

/// True when `run` is a URL scheme (`http`, `mongodb+srv`, …).
pub(super) fn is_scheme(run: &str) -> bool {
    let bytes = run.as_bytes();
    bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}
