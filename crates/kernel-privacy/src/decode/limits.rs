//! The decoding work caps, and the tokens left unresolved when one is hit.

use super::pass::{decode_once, Markers};

/// The whitespace-delimited ranges of `source` that one more decoding pass
/// would still change, whether or not [`MAX_PASSES`] was reached.
///
/// This is the same question [`DecodedText::unresolved`] asks of a view the
/// *decoder* stopped on, asked here of any text. The registry's composition
/// stops after a fixed number of rounds of decode and fold, so a
/// spelling deeper than that is not read: the ranges this returns are masked
/// whole rather than left clear.
///
/// [`DecodedText::unresolved`]: crate::decode::DecodedText::unresolved
pub(crate) fn tokens_still_encoded(source: &str) -> Vec<(usize, usize)> {
    let (decoded, local_bounds, _, _) = decode_once(source, Markers::Drop, None);
    let mut tokens: Vec<(usize, usize)> = Vec::new();
    for (ch, (start, end)) in decoded.chars().zip(local_bounds) {
        let mut bytes = [0u8; 4];
        let unchanged = source
            .get(start..end)
            .is_some_and(|found| found == ch.encode_utf8(&mut bytes));
        if unchanged || tokens.last().is_some_and(|last| start < last.1) {
            continue;
        }
        let from = source[..start]
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace())
            .map_or(0, |(at, c)| at + c.len_utf8());
        let to = source[end..]
            .find(char::is_whitespace)
            .map_or(source.len(), |at| end + at);
        tokens.push((from, to));
    }
    tokens
}

/// Decoding passes before the view is taken as final. Real mail nests one or
/// two layers; the cap keeps adversarial nesting linear.
pub const MAX_PASSES: usize = 16;

/// Ceiling used by kernel secret-echo decoding; reads and scans are charged.
pub const MAX_SECRET_DECODE_WORK: usize = 4 * 1024 * 1024;
