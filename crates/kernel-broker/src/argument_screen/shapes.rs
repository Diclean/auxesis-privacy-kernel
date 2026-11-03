//! The opaque identifier shapes: UUID, git SHA, SHA-256/512 digest, ULID, Calendar
//! event ID and Drive file ID.

use super::decode::decodes_to_text;

/// Whether `token` has the shape of an opaque identifier: a UUID, a git SHA, a
/// ULID, a Calendar event ID or a Drive file ID.
pub(super) fn is_opaque_token(token: &str) -> bool {
    is_uuid_or_sha(token)
        || is_calendar_event_id(token)
        || is_ulid(token)
        || is_drive_file_id(token)
}

/// Whether `token` is a UUID, a git SHA-1 or a SHA-256/SHA-512 hex digest:
/// fixed-shape identifiers whose digits are never a phone, and whose random hex
/// reads as an IBAN shape by chance.
pub(super) fn is_uuid_or_sha(token: &str) -> bool {
    is_uuid_shape(token) || is_git_sha(token) || is_hash_hex(token)
}

/// Whether `token` is a git SHA-1: forty hex digits.
fn is_git_sha(token: &str) -> bool {
    token.len() == 40 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether `token` is a bare SHA-256 or SHA-512 digest: 64 or 128 hex digits. It
/// is an opaque ID like a git SHA, so
/// [`is_false_hit`](super::false_hits::is_false_hit) drops its shape-only IBAN
/// and phone reads; a checksum-valid IBAN inside it still counts.
fn is_hash_hex(token: &str) -> bool {
    matches!(token.len(), 64 | 128) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether `token` is a Google Calendar event ID: base32hex, lowercase, at least
/// 26 characters, no padding. A run of only digits and `a`-`f` is hex and stays
/// with the hex rule, so it needs a letter from `g` to `v`.
pub(super) fn is_calendar_event_id(token: &str) -> bool {
    token.len() >= 26
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'v').contains(&byte))
        && token.bytes().any(|byte| (b'g'..=b'v').contains(&byte))
}

/// Whether `token` is a ULID: 26 characters of Crockford base32 in capitals, which
/// never use `I`, `L`, `O` or `U`.
pub(super) fn is_ulid(token: &str) -> bool {
    token.len() == 26
        && token.bytes().all(|byte| {
            byte.is_ascii_digit()
                || (byte.is_ascii_uppercase() && !matches!(byte, b'I' | b'L' | b'O' | b'U'))
        })
}

/// Whether `token` is a Google Drive file ID: 25 to 44 characters of the base64url
/// alphabet that do not decode to text. Such a run is an opaque ID, not hidden
/// data.
pub(super) fn is_drive_file_id(token: &str) -> bool {
    (25..=44).contains(&token.len())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && !decodes_to_text(token)
}

/// Whether `token` has the shape of a UUID: 36 characters with dashes, or the 32
/// hex digits of one written without dashes.
fn is_uuid_shape(token: &str) -> bool {
    let bytes = token.as_bytes();
    match bytes.len() {
        32 => bytes.iter().all(u8::is_ascii_hexdigit),
        36 => bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        }),
        _ => false,
    }
}
