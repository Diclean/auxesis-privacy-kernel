//! Dropping the false hits that opaque identifiers and epoch timestamps cause.

use kernel_privacy::recognizers::iban::{valid_iban, valid_iban_unknown};
use kernel_privacy::{EntityKind, Span};

use super::phone::is_epoch_shaped;
use super::shapes::{is_opaque_token, is_uuid_or_sha};

/// Whether a span is a false hit that an opaque identifier or an epoch timestamp
/// causes:
///
/// * epoch timestamps, alone or side by side, are never a phone;
/// * a phone inside one UUID, git SHA or SHA-256/512 digest token is not one: the
///   dashes of a UUID group its last twelve digits into a grouped number;
/// * an IBAN inside a Calendar event ID, Drive file ID, ULID, UUID, SHA or digest
///   token is not one unless its checksum holds: a random run carries a
///   two-letter, two-digit anchor that the shape-only fallback reads as an IBAN.
pub(super) fn is_false_hit(text: &str, span: &Span) -> bool {
    let raw = &text[span.start..span.end];
    let token = enclosing_token(text, span.start, span.end);
    match span.kind {
        EntityKind::Phone => only_epoch_numbers(raw) || is_uuid_or_sha(token),
        EntityKind::Iban => is_opaque_token(token) && !(valid_iban(raw) || valid_iban_unknown(raw)),
        _ => false,
    }
}

/// Whether `raw` is one or more whitespace-separated epoch timestamps.
fn only_epoch_numbers(raw: &str) -> bool {
    raw.split_whitespace().next().is_some() && raw.split_whitespace().all(is_epoch_shaped)
}

/// The whitespace- or `;`-delimited token of `text` that holds `start..end`.
fn enclosing_token(text: &str, start: usize, end: usize) -> &str {
    let is_break = |ch: char| ch.is_whitespace() || ch == ';';
    let begin = text[..start]
        .char_indices()
        .rev()
        .find(|(_, ch)| is_break(*ch))
        .map_or(0, |(at, ch)| at + ch.len_utf8());
    let finish = text[end..]
        .char_indices()
        .find(|(_, ch)| is_break(*ch))
        .map_or(text.len(), |(at, _)| end + at);
    &text[begin..finish]
}
