//! The marker runs the registry masks whole, and the tokens around them.

use crate::anonymize::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
use crate::span::Span;

/// Grow every span that overlaps a run of `runs` (sorted, disjoint) over that
/// whole run. A binary search per span finds its first run: linear-log.
pub(super) fn widen_over_runs(spans: &mut [Span], runs: &[(usize, usize)]) {
    if runs.is_empty() {
        return;
    }
    for span in spans {
        let mut at = runs.partition_point(|run| run.1 <= span.start);
        while at < runs.len() && runs[at].0 < span.end {
            span.start = span.start.min(runs[at].0);
            span.end = span.end.max(runs[at].1);
            at += 1;
        }
    }
}

/// Whether `source` is one token bracket and nothing else: how a view spells a
/// marker the source wrote plainly, since no fold reads as a bracket.
pub(super) fn is_bracket(source: &str) -> bool {
    let mut chars = source.chars();
    matches!(chars.next(), Some(PLACEHOLDER_OPEN | PLACEHOLDER_CLOSE)) && chars.next().is_none()
}

/// The whitespace-delimited token of `text` that holds the byte range
/// `(start, end)`. The fail-closed unit of the marker rules: a bracket hides
/// inside a token, so the whole token goes rather than the bracket alone.
pub(super) fn token_around(text: &str, start: usize, end: usize) -> (usize, usize) {
    let from = text[..start]
        .char_indices()
        .rev()
        .find(|(_, ch)| ch.is_whitespace())
        .map_or(0, |(at, ch)| at + ch.len_utf8());
    let to = text[end..]
        .find(char::is_whitespace)
        .map_or(text.len(), |at| end + at);
    (from, to)
}

/// The whitespace-bounded run of `text` around each marker, merged. `markers`
/// is sorted, so one forward pass is linear.
pub(super) fn marker_runs(text: &str, markers: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for &(start, end) in markers {
        let to = |end: usize| {
            text[end..]
                .find(char::is_whitespace)
                .map_or(text.len(), |at| end + at)
        };
        match runs.last_mut() {
            Some(last) if start < last.1 => {
                if end > last.1 {
                    last.1 = to(end);
                }
            }
            last => {
                let floor = last.map_or(0, |last| last.1);
                let from = text[floor..start]
                    .char_indices()
                    .rev()
                    .find(|(_, c)| c.is_whitespace())
                    .map_or(floor, |(at, c)| floor + at + c.len_utf8());
                runs.push((from, to(end)));
            }
        }
    }
    runs
}
