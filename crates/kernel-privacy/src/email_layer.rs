//! Email-aware detection layer.
//!
//! [`EmailLayer`] is the post-pass that closes the gap the deterministic
//! recognisers and GLiNER leave on messy e-mail: a bare first name in a
//! greeting, a name inside a `linkedin.example.invalid/in/jules-ferrand` path,
//! an address hidden behind `%40` in an unsubscribe link, a legal footer's
//! company number.
//!
//! It works in three steps:
//!
//! 1. **Decode** — [`crate::decode::DecodedText`] folds HTML entities and the percent escapes
//!    inside URLs, and every detection is mapped back to the original bytes.
//! 2. **Seed** — collect the names the text itself reveals: every `PERSON`
//!    span any recogniser found, every e-mail local part, every display name in
//!    a sender header or a "wrote" line, and every name a greeting, a sign-off
//!    or a `ps:` line names.
//! 3. **Propagate** — mask every other occurrence of each seeded token in the
//!    whole text (Unicode word boundary, case- and diacritic-insensitive),
//!    merging a first name and its surname when only a short separator sits
//!    between them. A stop-list keeps function words and public terms out.
//!
//! It also emits the deterministic company/tax identifiers
//! ([`crate::company_id`]), the whole value of a tracking or unsubscribe query
//! parameter, and a keyword-gated birth date in a flattened table. Finally it
//! drops an organisation or address span from a model when the value is an
//! allow-listed public term, unless the text carries a private signal too.
//!
//! Everything here fails toward masking: a rule that is unsure still masks.

use crate::public_terms::PublicTerms;

mod cues;
mod display;
mod function_words;
mod layer;
mod lines;
mod mail_words;
mod nameset;
mod propagate;
mod signals;
mod spans;
mod stop_words;

#[cfg(test)]
mod tests;

/// Score of a name reached by propagation from a seed.
pub const PROPAGATION_SCORE: f32 = 0.6;
/// Score of a name named directly by a greeting, sign-off, header or `ps:`.
pub const RULE_SCORE: f32 = 0.7;

/// The reserved app-config key that turns bare-first-name masking back on.
///
/// Default `false` (owner decision of 2026-10-09). The kernel-privacy switch is
/// [`EmailLayer::with_first_names`] / [`crate::RegistryBuilder::mask_first_names`].
/// The key is parsed by kernel-core as `PrivacyConfig::mask_first_names`; the
/// `[privacy] mask_first_names` contract is pinned by `tests/config_first_names.rs`.
pub const MASK_FIRST_NAMES_CONFIG_KEY: &str = "privacy.mask_first_names";

/// The layer and its configuration.
#[derive(Clone, Debug)]
pub struct EmailLayer {
    public_terms: PublicTerms,
    /// Whether a bare given name (a single token that is not a known surname
    /// and is not part of a full name) is masked on its own.
    ///
    /// Default `false`: the owner decision of 2026-10-09 ("non, prénom on s'en
    /// fout") keeps bare first names in clear. The app layer's config key is
    /// `[privacy] mask_first_names` (see [`EmailLayer::with_first_names`]).
    mask_first_names: bool,
}
