//! The `SafeText` boundary.
//!
//! [`SafeText`] is the only text a chat provider may receive. Its fields are
//! private and it has no public constructor, no `From<String>` and no
//! `Deserialize`, so it can be issued only by a [`Gate`], and a gate exists
//! only for a [`Grant`](kernel_core::privacy::Grant) minted by
//! `kernel_core::privacy::admit`. The gate runs the deterministic recognisers
//! (with the e-mail layer) and follows the grant's policy:
//!
//! * `GrantPolicy::Tokenised` (private mode): every detected value is replaced
//!   with a keyed `⟦KIND_…⟧` token, and the masked output is checked again. It
//!   fails closed: when detection errors, or the masked output still holds a
//!   detectable value, nothing is issued and the caller keeps the text local.
//! * `GrantPolicy::Passthrough` (open mode): the detectors still run, ordinary
//!   values are left in clear, and the [`DetectionReport`] returned next to the
//!   text names the kinds and counts private mode would have masked. The
//!   prohibited classes are the exception: a detected IBAN, payment card,
//!   national ID or passport, health term or secret is replaced with a fixed
//!   `[<class> removed]` marker (`[secret removed]` for a secret) rather than
//!   returned, because those classes never leave in any mode. No value is ever
//!   in the report.
//!
//! A production private gate hides no person's or company's name (owner,
//! 2026-10-19): it drops every `PERSON` and `ORGANIZATION` span and runs no name
//! model. The name sources (the known-names dictionary
//! [`crate::known_names::NameDictionary`], the e-mail layer's cues, GLiNER under
//! feature `ner-gliner`) still serve open mode's report and the eval.
//!
//! ```
//! use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
//! use kernel_privacy::safetext::Gate;
//!
//! let ctx = Context { destination: Destination::LocalDisplay };
//! let Decision::Allow(grant) = admit(PathId::C9, PrivacyMode::Open, &ctx) else {
//!     unreachable!("C9 is covered and allowed in open mode");
//! };
//! let mut gate = Gate::for_grant(&grant, [7u8; 32]);
//! let (safe, report) = gate.text("Bonjour, quelle heure est-il ?").unwrap();
//! assert_eq!(safe.as_str(), "Bonjour, quelle heure est-il ?");
//! assert_eq!(report.label(), "would have masked");
//! ```
//!
//! A raw string cannot become a [`SafeText`] outside this crate:
//!
//! ```compile_fail
//! let _ = kernel_privacy::safetext::SafeText::from(String::from("Élise Vautrin"));
//! ```
//!
//! ```compile_fail
//! let _ = kernel_privacy::safetext::SafeText("Élise Vautrin".to_string());
//! ```
//!
//! The round-1 literal path is gone as well. There is no hidden constructor
//! that takes a string — `&'static str` is exactly what `Box::leak`,
//! `OnceLock` and `LazyLock` produce — and no macro that reaches one:
//!
//! ```compile_fail,E0599
//! let _ = kernel_privacy::safetext::SafeText::__from_literal("[auxesis]");
//! ```
//!
//! ```compile_fail
//! let _ = kernel_privacy::safe_text_literal!("[auxesis]");
//! ```
//!
//! The only grantless path left is the crate-private `KernelMarker` enum: a
//! closed set of fixed strings written in this module, which no crate outside
//! `kernel-privacy` can name.

// The submodules are private on purpose: every item below is re-exported at
// this path, so `kernel_privacy::safetext::…` is exactly what it was before
// the split, and no new public path appears.

#[cfg(feature = "ner-gliner")]
mod deep;
mod detector;
mod gate;
mod names;
mod prohibited;
mod report;
mod residue;
mod safe_text;
mod tokens;

pub use detector::{Detector, StandardDetector, ASSISTANT_NAMES};
pub use gate::Gate;
pub use names::{
    install_local_name_model, install_name_spotter, name_spotter_installed, BoundedSpotter,
    NameSpotter, TwoPassDetector, LOCAL_MODEL_DIR,
};
pub use prohibited::export_column_ranges;
pub use report::{DetectError, DetectionReport, GateError};
#[cfg(test)]
pub(crate) use safe_text::KernelMarker;
pub use safe_text::{NameCoverage, SafeText, SafeValue};

#[cfg(test)]
mod second_pass_tests;
#[cfg(test)]
mod stand_in_tests;
#[cfg(test)]
mod tests;
