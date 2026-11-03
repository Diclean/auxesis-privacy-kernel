//! The `(token, original)` pairs one masking run returns.

use std::fmt;
use std::ops::Deref;

use zeroize::Zeroize;

/// The `(token, original)` pairs the caller stores in the vault.
///
/// The map keeps two views of the same masking run:
///
/// * `entries` is the *distinct* mapping, one `(token, first surface)` pair per
///   value, keyed by token (the token is an HMAC of the kind and the
///   *normalised* value, so `0612345678` and `06 12 34 56 78` share a token).
///   It is what the vault stores and what `Deref` exposes. Tokens here are
///   bare (`KIND_<fingerprint>`, no delimiters); the visible placeholder is the
///   delimited form written into masked text.
/// * `occurrences` is the *per-occurrence* list, `(token, exact surface)` in
///   masked-text order. A shared token can cover two different surface forms;
///   [`Anonymizer::restore`](crate::anonymize::Anonymizer::restore) walks this list to put each occurrence's exact
///   bytes back, so every masked occurrence round-trips byte for byte.
///
/// `Debug` prints only the tokens, so a stray log line can never leak a value.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TokenMap {
    pub(super) entries: Vec<(String, String)>,
    pub(super) occurrences: Vec<(String, String)>,
}

impl TokenMap {
    /// The number of distinct values.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no value has been seen yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The per-occurrence pairs in masked-text order. Crate-internal: the vault
    /// persists both views so [`Anonymizer::restore`](crate::anonymize::Anonymizer::restore) stays exact after a reload.
    pub(crate) fn occurrences(&self) -> &[(String, String)] {
        &self.occurrences
    }

    pub(crate) fn push_entry(&mut self, token: String, original: String) {
        self.entries.push((token, original));
    }

    pub(crate) fn push_occurrence(&mut self, token: String, original: String) {
        self.occurrences.push((token, original));
    }
}

impl Deref for TokenMap {
    type Target = [(String, String)];

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

/// Zeroes every token and value when the map is dropped, so a stored value
/// does not outlive its map in the heap. Best effort: a `Vec` that grew
/// earlier may have left unscrubbed copies in freed memory.
impl Drop for TokenMap {
    fn drop(&mut self) {
        for (token, original) in self.entries.iter_mut().chain(self.occurrences.iter_mut()) {
            token.zeroize();
            original.zeroize();
        }
    }
}

impl fmt::Debug for TokenMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tokens: Vec<&str> = self
            .entries
            .iter()
            .map(|(token, _)| token.as_str())
            .collect();
        f.debug_struct("TokenMap")
            .field("entries", &self.entries.len())
            .field("occurrences", &self.occurrences.len())
            .field("tokens", &tokens)
            .finish()
    }
}
