//! Errors and reports: why a gate refused, and the kind/count report it returns
//! with an issued text. Neither ever holds a value.

use std::collections::BTreeMap;
use std::fmt;

use kernel_core::privacy::GrantPolicy;

use crate::known_names::NameDictionaryError;
use crate::span::{EntityKind, Span};

/// Why detection could not produce a verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectError {
    /// A recogniser panicked.
    #[error("a recogniser failed")]
    Panicked,
    /// The name detector could not run (its model is missing or failed).
    #[error("the name detector failed")]
    Names,
    /// A secret-class block scalar is longer than the gate reads (8 KB). The gate
    /// refuses the text rather than mask part of the block; a longer value on its
    /// line is masked whole and never refused.
    #[error("a secret-class block is longer than the gate reads")]
    TooLong,
}

/// Why the gate refused to issue a [`SafeText`](super::SafeText) or
/// [`SafeValue`](super::SafeValue). Messages
/// never contain the refused text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    /// Local detection failed; the text stays local.
    #[error("local detection failed: {0}")]
    Detect(#[from] DetectError),
    /// The masked output still holds a detectable value; the text stays local.
    #[error("masked text still holds a detectable value")]
    Residue,
    /// No pseudonym key could be made; nothing is issued.
    #[error("no key for the outbound pseudonyms")]
    Key,
    /// The known-names dictionary could not be compiled; nothing is issued.
    #[error("the known-names dictionary could not be compiled")]
    Dictionary(#[from] NameDictionaryError),
}

/// What one gate call detected: the kinds and counts, never a value.
///
/// In open mode the report is what private mode **would have masked**, so the
/// caller can log `"would have masked"` and offer the upgrade; in private mode
/// it is what was masked (`"masked"`). Only [`EntityKind`] labels and counts
/// are held, so a report can be logged, audited or serialized without ever
/// carrying a raw value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionReport {
    label: &'static str,
    counts: BTreeMap<EntityKind, usize>,
}

impl DetectionReport {
    /// The audit label for a tokenising gate: values were replaced.
    pub const MASKED: &'static str = "masked";
    /// The audit label for a passthrough gate: values were left in clear.
    pub const WOULD_HAVE_MASKED: &'static str = "would have masked";

    pub(super) fn empty(policy: GrantPolicy) -> Self {
        Self {
            label: label_for(policy),
            counts: BTreeMap::new(),
        }
    }

    pub(super) fn of(policy: GrantPolicy, spans: &[Span]) -> Self {
        let mut report = Self::empty(policy);
        for span in spans {
            *report.counts.entry(span.kind).or_insert(0) += 1;
        }
        report
    }

    pub(super) fn merge(&mut self, other: Self) {
        for (kind, count) in other.counts {
            *self.counts.entry(kind).or_insert(0) += count;
        }
    }

    /// `"masked"` for a tokenising gate, `"would have masked"` for a
    /// passthrough one. This is the exact string the caller logs.
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// True when nothing detectable was found.
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Total number of detected spans.
    pub fn total(&self) -> usize {
        self.counts.values().sum()
    }

    /// How many spans of `kind` were detected.
    pub fn count(&self, kind: EntityKind) -> usize {
        self.counts.get(&kind).copied().unwrap_or(0)
    }

    /// The `(kind, count)` pairs, in the kind's stable order.
    pub fn counts(&self) -> impl Iterator<Item = (EntityKind, usize)> + '_ {
        self.counts.iter().map(|(kind, count)| (*kind, *count))
    }
}

impl fmt::Display for DetectionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label)?;
        if self.is_empty() {
            return write!(f, ": nothing detected");
        }
        write!(f, ":")?;
        for (kind, count) in self.counts() {
            write!(f, " {}={count}", kind.as_str())?;
        }
        Ok(())
    }
}

fn label_for(policy: GrantPolicy) -> &'static str {
    match policy {
        GrantPolicy::Passthrough => DetectionReport::WOULD_HAVE_MASKED,
        GrantPolicy::Tokenised => DetectionReport::MASKED,
    }
}
