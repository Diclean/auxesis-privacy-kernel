//! The K04 before/after runner (pre-1e pipeline against the email-aware one).

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::time::Instant;

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::{EntityKind, PublicTerms, Registry, Span};

use crate::cases::{cp_to_byte, Case};
use crate::tiers::is_name;

#[derive(Default)]
struct Totals {
    per_kind: BTreeMap<EntityKind, [usize; 3]>,
    gold: usize,
    covered: usize,
    trap_fp: usize,
    /// Gold person and organisation names, counted and never scored: they are
    /// not hidden by design, so they are in no recall, precision or region.
    names: usize,
    /// Region precision: merged predicted regions against merged gold regions.
    region_tp: usize,
    region_fp: usize,
    region_gold: usize,
    region_hit: usize,
    /// Same-kind false positives, `(kind, recogniser, value)`, for the
    /// over-masking drill.
    fps: Vec<(&'static str, &'static str, String)>,
    /// Every predicted span, `(kind, recogniser, value)`, when `AUX_EVAL_SPANS`.
    spans: Vec<(&'static str, &'static str, String)>,
    nanos: u128,
}

impl Totals {
    fn region_precision(&self) -> Option<f32> {
        ratio(self.region_tp, self.region_tp + self.region_fp)
    }

    fn region_recall(&self) -> Option<f32> {
        ratio(self.region_hit, self.region_gold)
    }

    fn overall_recall(&self) -> Option<f32> {
        let (tp, fn_): (usize, usize) = self.per_kind.values().fold((0, 0), |(tp, fn_), counts| {
            (tp + counts[0], fn_ + counts[2])
        });
        ratio(tp, tp + fn_)
    }

    fn overall_precision(&self) -> Option<f32> {
        let (tp, fp): (usize, usize) = self
            .per_kind
            .values()
            .fold((0, 0), |(tp, fp), counts| (tp + counts[0], fp + counts[1]));
        ratio(tp, tp + fp)
    }

    fn coverage(&self) -> Option<f32> {
        ratio(self.covered, self.gold)
    }
}

/// Whether a predicted span and a gold span share at least one byte.
fn overlaps(pred: &Span, gold: &GoldSpan) -> bool {
    pred.start < gold.end && gold.start < pred.end
}

/// Merge overlapping or adjacent spans into the regions the masker covers.
fn merged_regions(spans: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut sorted: Vec<(usize, usize)> = spans
        .iter()
        .copied()
        .filter(|(start, end)| start < end)
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

fn ratio(numerator: usize, denominator: usize) -> Option<f32> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f32 / denominator as f32)
    }
}

fn fmt_ratio(value: Option<f32>) -> String {
    match value {
        Some(v) => format!("{:.3}", v),
        None => "n/a".to_string(),
    }
}

/// Score one registry over every case.
fn measure(registry: &Registry, cases: &[Case], public: &PublicTerms, dump_fp: bool) -> Totals {
    let mut totals = Totals::default();
    let dump_spans = env::var("AUX_EVAL_SPANS").is_ok_and(|value| value != "0");
    let start = Instant::now();
    for case in cases {
        let mut gold: Vec<GoldSpan> = Vec::new();
        for labelled in &case.spans {
            let start = cp_to_byte(&case.text, labelled.start);
            let end = cp_to_byte(&case.text, labelled.end);
            if let Some(kind) = EntityKind::parse(&labelled.kind) {
                gold.push(GoldSpan::new(kind, start, end));
            }
        }
        // Names are counted and dropped: a missed name is not a miss, a
        // detected name is not a false positive, and neither enters a recall,
        // a precision or a region.
        totals.names += gold.iter().filter(|span| is_name(span.kind)).count();
        gold.retain(|span| !is_name(span.kind));
        let predicted: Vec<Span> = registry
            .analyze(&case.text)
            .into_iter()
            .filter(|span| !is_name(span.kind))
            .collect();
        if dump_spans {
            for pred in &predicted {
                if pred.start < pred.end && pred.end <= case.text.len() {
                    totals.spans.push((
                        pred.kind.as_str(),
                        pred.recognizer,
                        case.text[pred.start..pred.end].to_string(),
                    ));
                }
            }
        }
        totals.gold += gold.len();
        // Same-kind partial overlap, the matching rule the Python benchmark and
        // `examples/ner_eval.rs` use; a merged union still counts its members.
        for gold_span in &gold {
            let hit = predicted
                .iter()
                .any(|pred| pred.kind == gold_span.kind && overlaps(pred, gold_span));
            let entry = totals.per_kind.entry(gold_span.kind).or_insert([0, 0, 0]);
            if hit {
                entry[0] += 1;
            } else {
                entry[2] += 1;
            }
        }
        for pred in &predicted {
            let hit = gold
                .iter()
                .any(|gold_span| gold_span.kind == pred.kind && overlaps(pred, gold_span));
            let entry = totals.per_kind.entry(pred.kind).or_insert([0, 0, 0]);
            if !hit {
                entry[1] += 1;
                if dump_fp && pred.start < pred.end && pred.end <= case.text.len() {
                    totals.fps.push((
                        pred.kind.as_str(),
                        pred.recognizer,
                        case.text[pred.start..pred.end].to_string(),
                    ));
                }
            }
        }
        // Region precision: merge both sides first, so a separate span inside an
        // EMAIL or URL region is absorbed instead of counted twice.
        let gold_regions = merged_regions(
            &gold
                .iter()
                .map(|span| (span.start, span.end))
                .collect::<Vec<_>>(),
        );
        let pred_regions = merged_regions(
            &predicted
                .iter()
                .map(|span| (span.start, span.end))
                .collect::<Vec<_>>(),
        );
        for region in &pred_regions {
            if gold_regions
                .iter()
                .any(|gold| regions_overlap(region, gold))
            {
                totals.region_tp += 1;
            } else {
                totals.region_fp += 1;
            }
        }
        for region in &gold_regions {
            totals.region_gold += 1;
            if pred_regions
                .iter()
                .any(|pred| regions_overlap(region, pred))
            {
                totals.region_hit += 1;
            }
        }
        for gold_span in &gold {
            if predicted
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                totals.covered += 1;
            }
        }
        for pred in &predicted {
            if pred.start >= pred.end {
                continue;
            }
            if public.contains(&case.text[pred.start..pred.end]) {
                totals.trap_fp += 1;
            }
        }
    }
    totals.nanos = start.elapsed().as_nanos();
    totals
}

/// The K04 before/after table.
pub(crate) fn run_legacy(cases: &[Case], public: &PublicTerms) {
    let dump_fp = env::var("AUX_EVAL_FP").is_ok_and(|value| value != "0");

    let before = Registry::builder().with_all().without_email_layer().build();
    let after = Registry::new();
    let before = measure(&before, cases, public, dump_fp);
    let after = measure(&after, cases, public, dump_fp);

    let languages: BTreeSet<&str> = cases.iter().map(|case| case.lang.as_str()).collect();
    // Names get exactly one line here too: the corpus header. They are clear by
    // design, so there is no before/after to compare.
    println!(
        "corpus: {} cases [{}], {} gold spans, {} names not scored",
        cases.len(),
        languages.into_iter().collect::<Vec<_>>().join(","),
        before.gold,
        after.names
    );
    println!();
    println!("{:<22} {:>8} {:>8}", "metric", "before", "after");
    println!(
        "{:<22} {:>8} {:>8}",
        "overall recall",
        fmt_ratio(before.overall_recall()),
        fmt_ratio(after.overall_recall())
    );
    println!(
        "{:<22} {:>8} {:>8}",
        "span precision",
        fmt_ratio(before.overall_precision()),
        fmt_ratio(after.overall_precision())
    );
    println!(
        "{:<22} {:>8} {:>8}",
        "region precision",
        fmt_ratio(before.region_precision()),
        fmt_ratio(after.region_precision())
    );
    println!(
        "{:<22} {:>8} {:>8}",
        "region recall",
        fmt_ratio(before.region_recall()),
        fmt_ratio(after.region_recall())
    );
    println!(
        "{:<22} {:>8} {:>8}",
        "mask coverage",
        fmt_ratio(before.coverage()),
        fmt_ratio(after.coverage())
    );
    println!(
        "{:<22} {:>8} {:>8}",
        "trap FP", before.trap_fp, after.trap_fp
    );
    let overhead_ms = (after.nanos as f64 - before.nanos as f64) / 1e6;
    let per_case_us = (after.nanos as f64 - before.nanos as f64) / cases.len() as f64 / 1e3;
    println!(
        "layer overhead: {overhead_ms:.2} ms over {} cases ({per_case_us:.1} us/case)",
        cases.len()
    );
    println!();
    println!(
        "{:<16} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "kind", "rec B", "rec A", "prec B", "prec A", "fp B", "fp A"
    );
    for kind in EntityKind::ALL {
        let Some(before_counts) = before.per_kind.get(&kind) else {
            continue;
        };
        let after_counts = after.per_kind.get(&kind).copied().unwrap_or([0, 0, 0]);
        println!(
            "{:<16} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
            kind.as_str(),
            fmt_ratio(ratio(before_counts[0], before_counts[0] + before_counts[2])),
            fmt_ratio(ratio(after_counts[0], after_counts[0] + after_counts[2])),
            fmt_ratio(ratio(before_counts[0], before_counts[0] + before_counts[1])),
            fmt_ratio(ratio(after_counts[0], after_counts[0] + after_counts[1])),
            before_counts[1],
            after_counts[1]
        );
    }
    if dump_fp {
        println!();
        println!("after false positives ({}):", after.fps.len());
        let mut counts: BTreeMap<(&str, &str, &str), usize> = BTreeMap::new();
        for (kind, recognizer, value) in &after.fps {
            *counts
                .entry((kind, recognizer, value.as_str()))
                .or_default() += 1;
        }
        let mut sorted: Vec<((&str, &str, &str), usize)> = counts.into_iter().collect();
        sorted.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        for ((kind, recognizer, value), count) in sorted {
            println!("{count:>4}  {kind:<14} {recognizer:<24} {value:?}");
        }
    }
    if env::var("AUX_EVAL_SPANS").is_ok_and(|value| value != "0") {
        println!();
        for (kind, recognizer, value) in &after.spans {
            println!("SPAN\t{kind}\t{recognizer}\t{value}");
        }
    }
}
