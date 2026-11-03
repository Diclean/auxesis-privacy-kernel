//! The decoded and folded views the registry scans, and the chain between them.

use std::cell::Cell;
use std::sync::Arc;

use crate::decode::{self, DecodedText};
use crate::normalize::NormalizedText;

/// Which folds a pipeline run reads (NORM-GLYPH).
#[derive(Clone, Copy)]
pub(super) enum Folds {
    /// [`NormalizedText::folded_views`]: the views every scan reads.
    Main,
    /// [`NormalizedText::glyph_views`]: the extra views, unioned with the main ones.
    Glyph,
}

impl Folds {
    /// The views of `text` this run scans. A main run marks `glyph` when the
    /// glyph folds may read `text` another way, so the extra run is needed.
    pub(super) fn views(self, text: &str, glyph: &Cell<bool>) -> Vec<NormalizedText> {
        match self {
            Self::Main => {
                if NormalizedText::may_glyph_fold(text) {
                    glyph.set(true);
                }
                NormalizedText::folded_views(text)
            }
            Self::Glyph => NormalizedText::glyph_views(text),
        }
    }
}

/// A chain of decoded and folded views, from the source text to the view the
/// registry scans. Each step keeps its own map back to the step before it, so
/// composing the chain gives the map back to the source bytes.
pub(super) type Chain = Vec<Step>;

/// One step of a [`Chain`]: a decoded or folded view of the previous step's
/// text.
#[derive(Clone)]
pub(super) enum Step {
    Decoded(Arc<DecodedText>),
    Folded(NormalizedText),
}

impl Step {
    /// The text this step reads.
    fn text(&self) -> &str {
        match self {
            Self::Decoded(view) => view.text(),
            Self::Folded(view) => view.text(),
        }
    }

    /// A byte range of this step's text, as a range of the previous step's, or
    /// `None` when it is empty, out of bounds or off a char boundary.
    fn to_previous(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        match self {
            Self::Decoded(view) => view.source_bounds(start, end),
            Self::Folded(view) => view.to_original(start, end),
        }
    }
}

/// The text a chain reads: the text of its last step.
pub(super) fn chain_text(chain: &[Step]) -> &str {
    chain.last().expect("a chain has a step").text()
}

/// A byte range of a chain's text as a range of the source bytes, through every
/// step of the chain. Each step only widens a range, so the result still
/// covers every original byte of the value inside it.
pub(super) fn chain_bounds(chain: &[Step], start: usize, end: usize) -> Option<(usize, usize)> {
    let mut bounds = (start, end);
    for step in chain.iter().rev() {
        bounds = step.to_previous(bounds.0, bounds.1)?;
    }
    (bounds.0 < bounds.1).then_some(bounds)
}

/// The source ranges of `chain` a further decode would still change, each grown
/// to the whole source token around it. What NORM-2 masks at its pass cap.
pub(super) fn still_encoded(chain: &[Step]) -> Vec<(usize, usize)> {
    let Some(last) = chain.last() else {
        return Vec::new();
    };
    decode::tokens_still_encoded(last.text())
        .into_iter()
        .filter_map(|(start, end)| chain_bounds(chain, start, end))
        .collect()
}

/// A view's map from a span back to the original text's byte bounds.
pub(super) type SourceBounds<'a> = dyn Fn(usize, usize) -> Option<(usize, usize)> + 'a;
