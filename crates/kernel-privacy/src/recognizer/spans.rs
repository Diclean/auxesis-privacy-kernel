//! The span hygiene every detector's output goes through.

use crate::span::{EntityKind, Span};

use super::constants::{MAX_KEY_SPAN_BYTES, MAX_SPAN_BYTES};

/// Whether a span lies on UTF-8 boundaries and covers non-blank text.
///
/// Presidio's contract: a span whose `text[start..end]` is not the value
/// is dropped. Without a separate value we enforce the observable half: byte
/// ranges inside the text, on character boundaries, holding something other
/// than whitespace.
pub fn span_is_well_formed(text: &str, span: &Span) -> bool {
    if span.start >= span.end || span.end > text.len() {
        return false;
    }
    if !text.is_char_boundary(span.start) || !text.is_char_boundary(span.end) {
        return false;
    }
    let value = &text[span.start..span.end];
    !value.trim().is_empty()
}

/// Split every span longer than [`MAX_SPAN_BYTES`] (a secret: longer than
/// [`MAX_KEY_SPAN_BYTES`]) into consecutive pieces of at most [`MAX_SPAN_BYTES`]
/// bytes, each ending on a character boundary of `text`.
///
/// The pieces keep the parent span's kind, score and recogniser, so a merged
/// union cannot be used to mask an arbitrarily large region in one token while
/// still masking all of it. `text` must contain the span bounds on char
/// boundaries (spans are validated upstream).
pub fn split_long_spans(text: &str, spans: Vec<Span>) -> Vec<Span> {
    let mut out = Vec::with_capacity(spans.len());
    for span in spans {
        let whole = if span.kind == EntityKind::Secret {
            MAX_KEY_SPAN_BYTES
        } else {
            MAX_SPAN_BYTES
        };
        if span.len() <= whole {
            out.push(span);
            continue;
        }
        let mut start = span.start;
        while start < span.end {
            let mut end = (start + MAX_SPAN_BYTES).min(span.end);
            while end > start && !text.is_char_boundary(end) {
                end -= 1;
            }
            if end <= start {
                // A single code point longer than the cap: keep it whole.
                end = text[start..]
                    .char_indices()
                    .nth(1)
                    .map(|(offset, _)| start + offset)
                    .unwrap_or(span.end);
            }
            let mut piece = Span::new(span.kind, start, end, span.score, span.recognizer);
            piece.person_id = span.person_id;
            out.push(piece);
            start = end;
        }
    }
    out
}
