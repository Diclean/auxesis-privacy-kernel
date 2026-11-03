//! Merging the model's spans into the regions the masker sees.

use crate::span::Span;

/// Union every overlap that contains a prohibited span, keeping its full range
/// even when a higher-scoring ordinary label overlaps it.
pub fn consolidate(mut spans: Vec<Span>) -> Vec<Span> {
    spans.retain(|span| !span.is_empty());
    let mut regions = crate::recognizer::resolve_overlaps(spans.clone());
    let held = crate::recognizer::label_prohibited(&mut regions, &spans);
    let protected = regions
        .into_iter()
        .zip(held)
        .filter_map(|(region, held)| held.then_some(region));
    let ordinary = consolidate_flat(spans)
        .into_iter()
        .filter(|span| !span.is_prohibited())
        .collect::<Vec<_>>();
    let mut kept: Vec<Span> = protected.collect();
    kept.extend(ordinary);
    // Preserve the old stable start/end ordering, including tie order.
    kept.sort_by_key(|span| (span.start, span.end));
    kept
}

/// The flat score and overlap rule used before Tier C spans were unioned.
/// Keep this comparator and stable ordering unchanged for non-Tier-C labels.
pub(super) fn consolidate_flat(mut spans: Vec<Span>) -> Vec<Span> {
    spans.retain(|span| !span.is_empty());
    spans.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.start.cmp(&right.start))
            .then_with(|| left.end.cmp(&right.end))
    });
    // Kept spans are disjoint and non-empty, so a new span overlaps one of
    // them exactly when it overlaps the kept span with the greatest start
    // before its end: O(n log n) instead of a scan of every kept span.
    let mut starts: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    let mut kept: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        let overlaps = starts
            .range(..span.end)
            .next_back()
            .is_some_and(|(_, &end)| span.start < end);
        if !overlaps {
            starts.insert(span.start, span.end);
            kept.push(span);
        }
    }
    kept.sort_by_key(|span| (span.start, span.end));
    kept
}
