//! What `restore` does with a token it cannot resolve, and what it reports.

/// What [`Anonymizer::restore`](crate::anonymize::Anonymizer::restore) does with a delimited token that is not in the
/// session's [`TokenMap`](crate::anonymize::TokenMap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownPolicy {
    /// Leave the delimited token exactly as it appeared, so the caller can see
    /// what the model or the user invented. The report still names it.
    Keep,
    /// Replace the whole delimited token with [`UNKNOWN_REFERENCE`](crate::anonymize::UNKNOWN_REFERENCE), matching
    /// the kernel's screen and send rule.
    Redact,
}

/// The text [`Anonymizer::restore`](crate::anonymize::Anonymizer::restore) produced and what it could not resolve.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// The restored text: known placeholders rehydrated, escapes reversed.
    pub text: String,
    /// The bare tokens found inside delimiters that are not in this session's
    /// map, in text order. A non-empty list means the caller must hold the send
    /// ("unknown or invented tokens").
    pub unknown: Vec<String>,
}

impl RestoreReport {
    /// Whether every delimited token resolved to a session value.
    pub fn is_clean(&self) -> bool {
        self.unknown.is_empty()
    }
}
