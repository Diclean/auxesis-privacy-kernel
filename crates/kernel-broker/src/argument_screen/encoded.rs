//! Residue detection: whether a leaf still reads as encoded once decoding stops, and
//! what makes a hex or base64 run look encoded at all.

use super::decode::{decodes_to_text, hex_pair, is_base64_byte};
use super::shapes::{is_calendar_event_id, is_drive_file_id, is_ulid, is_uuid_or_sha};
use super::{
    MAX_DICTIONARY_WORD, MAX_ESCAPE_PERCENT, MIN_BASE64_CLASSES, MIN_BASE64_ENTROPY,
    MIN_BASE64_RUN, MIN_HEX_RUN,
};

/// Whether `text`, with decoding stopped, still reads as encoded: a `\u` escape
/// left over, a percent-escape share above [`MAX_ESCAPE_PERCENT`], or a
/// whitespace-separated token that is a hex or base64 run.
pub(super) fn looks_encoded(text: &str) -> bool {
    text.contains("\\u")
        || percent_escapes_over_limit(text)
        || text.split_whitespace().any(looks_encoded_token)
}

/// Whether the valid `%XX` escapes of `text` take up more than
/// [`MAX_ESCAPE_PERCENT`] per cent of its bytes.
fn percent_escapes_over_limit(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut escaped = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && bytes.get(index + 1..index + 3).and_then(hex_pair).is_some() {
            escaped += 3;
            index += 3;
        } else {
            index += 1;
        }
    }
    escaped * 100 > text.len() * MAX_ESCAPE_PERCENT
}

/// Whether one whitespace-separated token is a hex run of at least
/// [`MIN_HEX_RUN`] digits, or a base64 run that looks encoded and decodes to text.
/// Opaque identifier shapes are never encoded data: a UUID, a git SHA and a bare
/// SHA-256 or SHA-512 hex digest are exempt, a ULID or a Calendar event ID is
/// exempt by shape, and a Drive file ID is exempt unless its base64 decoding is
/// text.
pub(super) fn looks_encoded_token(token: &str) -> bool {
    if is_uuid_or_sha(token) {
        return false;
    }
    let body = token.trim_end_matches('=');
    let padding = token.len() - body.len();
    if token.len() >= MIN_HEX_RUN && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return true;
    }
    if is_calendar_event_id(token) || is_ulid(token) || is_drive_file_id(token) {
        return false;
    }
    let mixes_alphabets = body.bytes().any(|byte| matches!(byte, b'+' | b'/'))
        && body.bytes().any(|byte| matches!(byte, b'-' | b'_'));
    let base64 = body.len() >= MIN_BASE64_RUN
        && padding <= 2
        && (padding == 0 || token.len().is_multiple_of(4))
        && body.len() % 4 != 1
        && !mixes_alphabets
        && body.bytes().all(is_base64_byte)
        && character_classes(token) >= MIN_BASE64_CLASSES
        && shannon_entropy(token) >= MIN_BASE64_ENTROPY
        && !dictionary_like(token);
    base64 && decodes_to_text(body)
}

/// How many of the four character classes `token` uses: upper case, lower case,
/// digits, and `+/=-_`.
fn character_classes(token: &str) -> usize {
    [
        token.bytes().any(|byte| byte.is_ascii_uppercase()),
        token.bytes().any(|byte| byte.is_ascii_lowercase()),
        token.bytes().any(|byte| byte.is_ascii_digit()),
        token
            .bytes()
            .any(|byte| matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')),
    ]
    .into_iter()
    .filter(|&present| present)
    .count()
}

/// The Shannon entropy of `text`, in bits per byte.
fn shannon_entropy(text: &str) -> f64 {
    let mut counts = [0usize; 256];
    for byte in text.bytes() {
        counts[usize::from(byte)] += 1;
    }
    let total = text.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

/// Whether `token` is dictionary-like words joined by `_` or `-`: every part is
/// alphabetic and at most [`MAX_DICTIONARY_WORD`] characters. Such a run is a
/// snake_case or kebab-case key or label, not encoded data.
fn dictionary_like(token: &str) -> bool {
    token.contains(['_', '-'])
        && token.split(['_', '-']).all(|part| {
            part.len() <= MAX_DICTIONARY_WORD && part.bytes().all(|byte| byte.is_ascii_alphabetic())
        })
}
