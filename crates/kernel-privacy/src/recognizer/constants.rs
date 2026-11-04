//! The scores and caps the registry, the detectors and the masker share.

/// Confidence given to a span from a recogniser whose rule is not verified.
///
/// Lower than a verified hit (`1.0`) but still above the generic floor: an
/// unverified rule still masks, it just labels the span `NATIONAL_ID`.
pub const UNVERIFIED_SCORE: f32 = 0.6;

/// Confidence for a checksum-valid value with no cue and no verified rule.
///
/// The registry never drops such a value: it relabels it `NATIONAL_ID` at this
/// score, so masking fails toward masking (maintainer policy for this masker).
pub const GENERIC_FALLBACK_SCORE: f32 = 0.6;

/// Longest span, in bytes: a longer detection is split into pieces at or below
/// this length (on character boundaries) instead of masking a huge region.
pub const MAX_SPAN_BYTES: usize = 128;

/// Longest API key kept as one token, in bytes. A provider key is one secret
/// and a wrapped one runs well past [`MAX_SPAN_BYTES`]; a key longer than this
/// still splits, so a token stays bounded.
pub const MAX_KEY_SPAN_BYTES: usize = 512;

/// Rounds of decode and fold the registry composes. A fold creates
/// escapes of its own (`＆` folds to `&`, so `&#105;` reads only after a second
/// decode) and what that escape reads folds again. Real mail nests one or two
/// layers; the cap keeps adversarial nesting a fixed number of linear passes.
pub(super) const COMPOSITION_ROUNDS: usize = 3;

/// The recogniser label of a marker run that splices a word: it fails closed.
pub(crate) const MARKER_RUN: &str = "marker";

/// The label of a prohibited region a name widened, for a registry without names.
pub(crate) const NAME_WIDENED: &str = "name-widened";
