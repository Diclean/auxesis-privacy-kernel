//! The [`Recognizer`] trait: the contract every deterministic detector meets.

use crate::span::{EntityKind, Span};

/// A deterministic detector for one or more [`EntityKind`]s.
pub trait Recognizer: Send + Sync {
    /// The kinds this recogniser can emit.
    fn kinds(&self) -> &[EntityKind];

    /// Find every value of the declared kinds in `text`.
    fn analyze(&self, text: &str) -> Vec<Span>;

    /// Find values in a transformed view while retaining its mapping to the
    /// original input. Recognisers that use source token boundaries can
    /// override this; other recognisers keep their existing view-only scan.
    fn analyze_with_source(
        &self,
        text: &str,
        _original: &str,
        _source_bounds: &dyn Fn(usize, usize) -> Option<(usize, usize)>,
    ) -> Vec<Span> {
        self.analyze(text)
    }

    /// A short stable name, echoed in [`Span::recognizer`].
    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    /// Whether the rule has been checked against an official source.
    fn verified(&self) -> bool {
        true
    }

    /// Whether the default registry mounts this recogniser.
    ///
    /// Since the masker must fail toward masking, an unverified rule is still
    /// mounted: `verified` only controls the score and the label
    /// ([`UNVERIFIED_SCORE`](crate::recognizer::UNVERIFIED_SCORE)), never whether a checksum-valid value is masked.
    fn enabled_by_default(&self) -> bool {
        true
    }
}
