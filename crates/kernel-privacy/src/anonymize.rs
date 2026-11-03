//! Stable per-session pseudonyms for detected values.
//!
//! Each surviving [`Span`](crate::span::Span) becomes a delimited `⟦KIND_<fingerprint>⟧`
//! placeholder. The token inside the delimiters is *not* a hash of the value:
//! it is the hex of the first bytes of an HMAC-SHA-256 (keyed from the vault)
//! over the kind and the normalised value, so two occurrences of one value get
//! the same token, a fresh session key gives different tokens, and a captured
//! token cannot be reversed by a dictionary attack. The caller receives the
//! `(token, original)` pairs and stores them in the vault, so
//! [`Anonymizer::restore`] returns the exact original bytes.
//!
//! A literal opener `⟦` (U+27E6) already in the input is written doubled
//! (`⟦⟦`) during [`Anonymizer::anonymize`]. Nothing else is rewritten:
//! backslashes, the closer `⟧` (U+27E7) and every other character pass through
//! byte-identical. A real token never starts with `⟦⟦`, so a user, a model or an
//! attacker cannot plant a token-shaped string that `restore` would mistake for
//! one of ours. `restore` reads left to right in a single pass: `⟦⟦` is one
//! literal `⟦`, and `⟦` followed by a token and `⟧` is a placeholder. Undelimited
//! token-like text is never touched.
//!
//! A value never appears in a token, in this type's `Debug` output, in
//! [`TokenMap`]'s `Debug` output, or in a log line.

mod anonymizer;
mod escape;
mod normalize;
mod placeholder;
mod policy;
mod restore;
mod token_map;

pub use anonymizer::Anonymizer;
pub use placeholder::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN, UNKNOWN_REFERENCE};
pub use policy::{RestoreReport, UnknownPolicy};
pub use restore::restore;
pub use token_map::TokenMap;

pub(crate) use normalize::{casefold, kind_of_token, normalize_value};

#[cfg(test)]
mod tests;
