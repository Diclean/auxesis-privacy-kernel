//! The [`Recognizer`] trait and the [`Registry`] that runs a set of them.
//!
//! The registry is the deterministic half of the Presidio architecture: it
//! runs every enabled recogniser, validates each span against the original
//! UTF-8 text, applies the context enhancer, applies per-kind thresholds, and
//! resolves overlaps.

// The submodules are private on purpose: every item below is re-exported at
// this path, so `crate::recognizer::…` is exactly what it was before the
// split, and no new public path appears.
mod builder;
mod constants;
mod detector;
mod markers;
mod overlap;
mod person;
mod pipeline;
mod registry;
mod spans;

#[cfg(test)]
mod tests;

pub use builder::RegistryBuilder;
pub use constants::{GENERIC_FALLBACK_SCORE, MAX_KEY_SPAN_BYTES, MAX_SPAN_BYTES, UNVERIFIED_SCORE};
pub use detector::Recognizer;
pub use overlap::resolve_overlaps;
pub use registry::Registry;
pub use spans::{span_is_well_formed, split_long_spans};

pub(crate) use constants::{MARKER_RUN, NAME_WIDENED};
pub(crate) use overlap::{label_prohibited, masked_regions};
pub(crate) use person::extend_hyphenated_persons;
