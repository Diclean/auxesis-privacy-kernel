//! Local GLiNER2-PII NER recogniser, behind the `ner-gliner` feature: the span
//! engine the deterministic [`crate::Registry`] cannot provide. Called by
//! [`crate::safetext::Gate::for_grant_with_gliner`], by the Deep detector
//! that gate builds, and by [`crate::safetext::install_local_name_model`].
//!
//! GLiNER2 is a zero-shot span tagger: the caller supplies the entity labels in
//! the prompt and the model returns byte spans and probabilities for them. The
//! runner is the reusable `gliner2-rs` crate (`crates/gliner2`); this module
//! maps its entities onto the kernel's
//! [`EntityKind`](crate::span::EntityKind)s, keeps the fail-closed rules, and
//! exposes the recogniser the registry and the gate use.
//!
//! Properties the kernel relies on:
//!
//! * **No Python at runtime and no network.** The ONNX graph, the fast
//!   tokenizer and the ONNX Runtime dylib are local files under a
//!   user-configured directory; nothing is bundled in the repository.
//! * **Byte-accurate spans.** Every span is checked against the source bytes
//!   by the runner; a mismatch is dropped and counted, never guessed.
//! * **Long text is chunked, never truncated.** The runner splits a long text
//!   into overlapping token windows and shifts the spans back into the text.
//! * **Fail closed.** [`GlinerRecognizer::load`] and
//!   [`GlinerRecognizer::analyze_report`] return a [`GlinerError`] on a missing
//!   model, a bad tokenizer or an inference failure. Nothing returns "no
//!   entities" on error.
//!
//! The [`Recognizer`](crate::recognizer::Recognizer) trait cannot carry an
//! error. Its adapter
//! ([`GlinerRecognizer::analyze`](crate::recognizer::Recognizer::analyze))
//! therefore fails toward masking: on error it returns one span covering the
//! whole text and records the error, which
//! [`GlinerRecognizer::take_error`] hands back to the caller. Code that can
//! propagate the failure should call [`GlinerRecognizer::analyze_report`].

// The submodules are private on purpose: every item below is re-exported at
// this path, so `crate::ner::…` is exactly what it was before the split, and
// no new public path appears.
mod config;
mod consolidate;
mod error;
mod labels;
mod local;
mod recognizer;

#[cfg(test)]
mod tests;

pub use config::GlinerConfig;
pub use consolidate::consolidate;
pub use error::GlinerError;
pub use labels::{
    label_kind, DEFAULT_CHUNK_OVERLAP, DEFAULT_CHUNK_TOKENS, DEFAULT_MAX_WIDTH, DEFAULT_THRESHOLD,
    GLINER_PII_LABELS, LABEL_THRESHOLDS, NAME_THRESHOLD,
};
pub use local::{install_local_model, load_vetted_local_model, MAX_SPOT_BYTES, SPOT_DEADLINE};
pub use recognizer::{GlinerRecognizer, GlinerReport};
