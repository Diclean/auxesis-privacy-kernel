//! Escaping a literal placeholder opener in clear text.

use super::placeholder::PLACEHOLDER_OPEN;

/// Append `clear` to `out`, doubling every literal opener.
///
/// This is the only rewrite [`Anonymizer::restore`](crate::anonymize::Anonymizer::restore) reverses: `⟦` becomes
/// `⟦⟦`. Every other character, backslashes included, is copied unchanged.
pub(super) fn push_escaped(out: &mut String, clear: &str) {
    for ch in clear.chars() {
        out.push(ch);
        if ch == PLACEHOLDER_OPEN {
            out.push(PLACEHOLDER_OPEN);
        }
    }
}
