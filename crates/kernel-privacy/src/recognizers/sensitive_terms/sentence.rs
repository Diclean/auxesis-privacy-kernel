//! The sentence window that anchors an ambiguous hit.

use crate::span::Span;

/// How far the sentence check looks each side of a contextual hit, in bytes:
/// a sentence longer than this is cut, which keeps the scan linear.
const SENTENCE_WINDOW: usize = 512;

/// Whether a character ends a sentence for the health-anchor check.
pub(super) fn is_sentence_end(ch: char) -> bool {
    matches!(ch, '.' | '!' | '?' | ';' | '\n' | '。' | '！' | '？' | '；')
}

/// The largest character boundary at or before `at`.
pub(super) fn char_floor(text: &str, mut at: usize) -> usize {
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// The smallest character boundary at or after `at`.
fn char_ceil(text: &str, mut at: usize) -> usize {
    while at < text.len() && !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

/// Whether a health anchor (a strong term or a cue, by start offset in
/// `anchors`) starts in the sentence around `span`, outside the span itself: a
/// disease name never anchors itself (`Mark's disease`).
pub(super) fn cued(text: &str, span: Span, anchors: &[usize]) -> bool {
    let from = char_floor(text, span.start.saturating_sub(SENTENCE_WINDOW));
    let low = text[from..span.start]
        .char_indices()
        .rev()
        .find(|(_, ch)| is_sentence_end(*ch))
        .map_or(from, |(at, ch)| from + at + ch.len_utf8());
    let to = char_ceil(text, (span.end + SENTENCE_WINDOW).min(text.len()));
    let high = text[span.end..to]
        .char_indices()
        .find(|(_, ch)| is_sentence_end(*ch))
        .map_or(to, |(at, _)| span.end + at);
    let first = anchors.partition_point(|&start| start < low);
    anchors[first..]
        .iter()
        .take_while(|&&start| start < high)
        .any(|&start| start < span.start || start >= span.end)
}
