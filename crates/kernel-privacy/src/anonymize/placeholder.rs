//! Placeholder delimiters and the marker for an unresolved token.

/// Opens a placeholder: `⟦` (U+27E6 LEFT WHITE SQUARE BRACKET).
pub const PLACEHOLDER_OPEN: char = '\u{27E6}';
/// Closes a placeholder: `⟧` (U+27E7 RIGHT WHITE SQUARE BRACKET).
pub const PLACEHOLDER_CLOSE: char = '\u{27E7}';

/// The marker [`UnknownPolicy::Redact`](crate::anonymize::UnknownPolicy::Redact) writes for a token that is not in the
/// session's map. Matches the kernel's screen and send rule: a token that is
/// not in the map is never shown, it is replaced.
pub const UNKNOWN_REFERENCE: &str = "[unknown reference]";
