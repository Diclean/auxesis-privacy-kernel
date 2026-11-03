//! The union views of a case: the deterministic/model union, the email-layer
//! union and the non-overlapping regions the masker covers.

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::span::EntityKind;
use kernel_privacy::EmailLayer;

use super::scoring::overlap;

pub(crate) fn as_gold(spans: &[kernel_privacy::Span]) -> Vec<GoldSpan> {
    spans
        .iter()
        .map(|span| GoldSpan::new(span.kind, span.start, span.end))
        .collect()
}

pub(crate) fn union(
    deterministic: Vec<kernel_privacy::Span>,
    predicted: &[kernel_privacy::Span],
) -> Vec<GoldSpan> {
    let mut spans = deterministic;
    spans.extend_from_slice(predicted);
    as_gold(&kernel_privacy::recognizer::resolve_overlaps(spans))
}

/// Merge overlapping or adjacent spans into the regions the masker covers.
///
/// This is the non-overlapping union view (kind dropped), so a `PERSON` span
/// kept inside an `EMAIL` or `URL` region for the kind-aware audit is absorbed
/// instead of counted a second time.
fn merged_regions(spans: &[GoldSpan]) -> Vec<(usize, usize)> {
    let mut sorted: Vec<(usize, usize)> = spans
        .iter()
        .filter(|span| span.start < span.end)
        .map(|span| (span.start, span.end))
        .collect();
    sorted.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn regions_overlap(left: &(usize, usize), right: &(usize, usize)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

/// `(true positives, false positives, gold regions, recalled gold regions)`.
pub(crate) fn region_counts(
    gold: &[GoldSpan],
    predicted: &[GoldSpan],
) -> (usize, usize, usize, usize) {
    let gold_regions = merged_regions(gold);
    let pred_regions = merged_regions(predicted);
    let mut true_positives = 0usize;
    for region in &pred_regions {
        if gold_regions
            .iter()
            .any(|gold| regions_overlap(region, gold))
        {
            true_positives += 1;
        }
    }
    let false_positives = pred_regions.len() - true_positives;
    let recalled = gold_regions
        .iter()
        .filter(|gold| pred_regions.iter().any(|pred| regions_overlap(gold, pred)))
        .count();
    (
        true_positives,
        false_positives,
        gold_regions.len(),
        recalled,
    )
}

/// Kind-agnostic name recall: any predicted kind may cover a gold `PERSON`.
pub(crate) fn agnostic_name_counts(gold: &[GoldSpan], predicted: &[GoldSpan]) -> (usize, usize) {
    let mut hit = 0usize;
    let mut total = 0usize;
    for gold_span in gold.iter().filter(|span| span.kind == EntityKind::Person) {
        total += 1;
        if predicted.iter().any(|pred| overlap(pred, gold_span)) {
            hit += 1;
        }
    }
    (hit, total)
}

pub(crate) fn region_precision(counts: (usize, usize, usize, usize)) -> f64 {
    let denominator = counts.0 + counts.1;
    if denominator == 0 {
        1.0
    } else {
        counts.0 as f64 / denominator as f64
    }
}

pub(crate) fn region_recall(counts: (usize, usize, usize, usize)) -> f64 {
    if counts.2 == 0 {
        1.0
    } else {
        counts.3 as f64 / counts.2 as f64
    }
}

pub(crate) fn agnostic_name_recall(counts: (usize, usize)) -> f64 {
    if counts.1 == 0 {
        1.0
    } else {
        counts.0 as f64 / counts.1 as f64
    }
}

/// The production pipeline with the model mounted: deterministic candidates and
/// model spans go through the email-aware layer together, so the public-term
/// allowlist sees the model's organisation and address spans.
pub(crate) fn after_union(
    layer: &EmailLayer,
    deterministic: Vec<kernel_privacy::Span>,
    predicted: &[kernel_privacy::Span],
    text: &str,
) -> Vec<GoldSpan> {
    let mut candidates = deterministic;
    let seeds: Vec<kernel_privacy::Span> = predicted
        .iter()
        .filter(|span| span.kind == EntityKind::Person)
        .copied()
        .collect();
    candidates.extend_from_slice(predicted);
    as_gold(&kernel_privacy::recognizer::resolve_overlaps(
        layer.apply(text, candidates, &seeds),
    ))
}
