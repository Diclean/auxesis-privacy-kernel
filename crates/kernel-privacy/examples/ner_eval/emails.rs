//! The messy-email before/after comparison for the two registries.

use std::collections::BTreeMap;
use std::time::Instant;

use kernel_privacy::span::EntityKind;
use kernel_privacy::{EmailLayer, GlinerRecognizer, PublicTerms, Registry};
use serde_json::{json, Value};

use super::corpus::Case;
use super::patterns::{person_patterns, trap_fp, PatternScore};
use super::regions::{
    agnostic_name_counts, agnostic_name_recall, as_gold, region_counts, region_precision,
    region_recall, union,
};
use super::scoring::{overlap, score, Score};

/// The messy-email before/after comparison for both registries.
pub(crate) fn email_report(
    recognizer: &GlinerRecognizer,
    before: &Registry,
    deterministic: &Registry,
    layer: &EmailLayer,
    cases: &[Case],
    public: &PublicTerms,
) -> Value {
    let mut before_union = Score::default();
    let mut after_union_score = Score::default();
    let mut before_names = Score::default();
    let mut after_names = Score::default();
    let mut det_span = Score::default();
    let mut det_names = Score::default();
    let mut det_agnostic = (0usize, 0usize);
    let mut det_region = (0usize, 0usize, 0usize, 0usize);
    let mut det_covered = 0usize;
    let det_missed_enabled = std::env::var("AUX_GLINER_FN").is_ok_and(|value| value != "0");
    let mut det_missed: Vec<String> = Vec::new();
    let mut union_missed: Vec<String> = Vec::new();
    let mut det_trap = 0usize;
    let mut before_agnostic = (0usize, 0usize);
    let mut after_agnostic = (0usize, 0usize);
    let mut before_region = (0usize, 0usize, 0usize, 0usize);
    let mut after_region = (0usize, 0usize, 0usize, 0usize);
    let mut ner_precision = Score::default();
    let mut before_covered = 0usize;
    let mut after_covered = 0usize;
    let mut before_trap = 0usize;
    let mut after_trap = 0usize;
    let mut gold_total = 0usize;
    let mut patterns: BTreeMap<&'static str, PatternScore> = BTreeMap::new();
    let mut before_overhead = std::time::Duration::ZERO;
    let mut after_overhead = std::time::Duration::ZERO;

    for case in cases {
        let report = recognizer.analyze_report(&case.text).expect("recognize");
        let predicted = report.spans;
        let predicted_gold = as_gold(&predicted);
        ner_precision.add(&score(&case.gold, &predicted_gold, false));

        // Deterministic-only config: the production registry (email layer
        // mounted, no model), exactly what `privacy-eval` scores.
        let det_spans = as_gold(&deterministic.analyze(&case.text));
        det_span.add(&score(&case.gold, &det_spans, false));
        det_names.add(&score(&case.gold, &det_spans, true));
        let det_agnostic_score = agnostic_name_counts(&case.gold, &det_spans);
        det_agnostic.0 += det_agnostic_score.0;
        det_agnostic.1 += det_agnostic_score.1;
        let det_region_score = region_counts(&case.gold, &det_spans);
        det_region.0 += det_region_score.0;
        det_region.1 += det_region_score.1;
        det_region.2 += det_region_score.2;
        det_region.3 += det_region_score.3;
        for gold_span in &case.gold {
            if det_spans
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                det_covered += 1;
            }
            if det_missed_enabled
                && gold_span.kind == EntityKind::Person
                && !det_spans.iter().any(|pred| overlap(pred, gold_span))
            {
                det_missed.push(case.text[gold_span.start..gold_span.end].to_string());
            }
        }
        det_trap += trap_fp(&det_spans, &case.text, public);
        gold_total += case.gold.len();

        let start = Instant::now();
        let before_spans = before.analyze(&case.text);
        before_overhead += start.elapsed();
        let before_union_spans = union(before_spans.clone(), &predicted);
        let mut candidates = before_spans;
        candidates.extend_from_slice(&predicted);
        let seeds: Vec<kernel_privacy::Span> = predicted
            .iter()
            .filter(|span| span.kind == EntityKind::Person)
            .copied()
            .collect();
        let start = Instant::now();
        let layered = layer.apply(&case.text, candidates, &seeds);
        after_overhead += start.elapsed();
        let after_union_spans = as_gold(&kernel_privacy::recognizer::resolve_overlaps(layered));
        if det_missed_enabled {
            for gold_span in &case.gold {
                if gold_span.kind == EntityKind::Person
                    && !after_union_spans
                        .iter()
                        .any(|pred| overlap(pred, gold_span))
                {
                    union_missed.push(case.text[gold_span.start..gold_span.end].to_string());
                }
            }
        }
        let before_score = score(&case.gold, &before_union_spans, false);
        let after_score = score(&case.gold, &after_union_spans, false);
        before_union.add(&before_score);
        after_union_score.add(&after_score);
        before_names.add(&score(&case.gold, &before_union_spans, true));
        after_names.add(&score(&case.gold, &after_union_spans, true));
        let before_agnostic_score = agnostic_name_counts(&case.gold, &before_union_spans);
        before_agnostic.0 += before_agnostic_score.0;
        before_agnostic.1 += before_agnostic_score.1;
        let after_agnostic_score = agnostic_name_counts(&case.gold, &after_union_spans);
        after_agnostic.0 += after_agnostic_score.0;
        after_agnostic.1 += after_agnostic_score.1;
        let before_region_score = region_counts(&case.gold, &before_union_spans);
        before_region.0 += before_region_score.0;
        before_region.1 += before_region_score.1;
        before_region.2 += before_region_score.2;
        before_region.3 += before_region_score.3;
        let after_region_score = region_counts(&case.gold, &after_union_spans);
        after_region.0 += after_region_score.0;
        after_region.1 += after_region_score.1;
        after_region.2 += after_region_score.2;
        after_region.3 += after_region_score.3;

        for gold_span in &case.gold {
            if before_union_spans
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                before_covered += 1;
            }
            if after_union_spans
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                after_covered += 1;
            }
            if gold_span.kind == EntityKind::Person {
                let recalled = after_union_spans
                    .iter()
                    .any(|pred| pred.kind == EntityKind::Person && overlap(pred, gold_span));
                for pattern in person_patterns(case, gold_span) {
                    let entry = patterns.entry(pattern).or_default();
                    entry.gold += 1;
                    if recalled {
                        entry.recalled += 1;
                    }
                }
            }
        }
        for (spans, counter) in [
            (&before_union_spans, &mut before_trap),
            (&after_union_spans, &mut after_trap),
        ] {
            for pred in spans.iter() {
                if pred.kind == EntityKind::Person || pred.start >= pred.end {
                    continue;
                }
                if public.contains(&case.text[pred.start..pred.end]) {
                    *counter += 1;
                }
            }
        }
    }

    let mut pattern_map = serde_json::Map::new();
    for (pattern, entry) in &patterns {
        pattern_map.insert(
            (*pattern).to_string(),
            json!({
                "gold": entry.gold,
                "recalled": entry.recalled,
                "recall": if entry.gold == 0 { 1.0 } else { entry.recalled as f64 / entry.gold as f64 },
            }),
        );
    }

    json!({
        "cases": cases.len(),
        "gold": gold_total,
        "deterministic": {
            "span_precision": det_span.precision(),
            "span_recall": det_span.recall(),
            "name_recall": det_names.recall(),
            "name_recall_agnostic": agnostic_name_recall(det_agnostic),
            "region_precision": region_precision(det_region),
            "region_recall": region_recall(det_region),
            "mask_coverage": if gold_total == 0 { 1.0 } else { det_covered as f64 / gold_total as f64 },
            "trap_fp": det_trap,
        },
        "before": {
            "union_recall": before_union.recall(),
            "union_precision": before_union.precision(),
            "name_recall": before_names.recall(),
            "name_recall_agnostic": agnostic_name_recall(before_agnostic),
            "region_precision": region_precision(before_region),
            "region_recall": region_recall(before_region),
            "mask_coverage": if gold_total == 0 { 1.0 } else { before_covered as f64 / gold_total as f64 },
            "trap_fp": before_trap,
        },
        "after": {
            "union_recall": after_union_score.recall(),
            "union_precision": after_union_score.precision(),
            "name_recall": after_names.recall(),
            "name_recall_agnostic": agnostic_name_recall(after_agnostic),
            "region_precision": region_precision(after_region),
            "region_recall": region_recall(after_region),
            "mask_coverage": if gold_total == 0 { 1.0 } else { after_covered as f64 / gold_total as f64 },
            "trap_fp": after_trap,
        },
        "ner_precision": ner_precision.precision(),
        "deterministic_missed_persons": det_missed,
        "union_missed_persons": union_missed,
        "registry_ms_before": before_overhead.as_secs_f64() * 1000.0,
        "layer_ms": after_overhead.as_secs_f64() * 1000.0,
        "layer_us_per_case": after_overhead.as_secs_f64() * 1e6 / cases.len().max(1) as f64,
        "per_pattern": Value::Object(pattern_map),
    })
}
