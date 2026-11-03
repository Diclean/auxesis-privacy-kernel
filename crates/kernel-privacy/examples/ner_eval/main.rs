//! Score the local GLiNER recogniser, alone and unioned with the deterministic
//! registry, on the FAKE `qa/privacy-eval` corpus.
//!
//! This is the slice-1d/1e gate harness. It runs the Rust recogniser over the
//! corpus, compares its byte spans with the gold spans with the same matching
//! rule the Python benchmark used (same kind and a partial overlap), reports
//! per-language name recall and overall recall/precision, times short messages
//! and synthetic long threads, reads the process peak RSS, and repeats
//! everything for the union with the deterministic `Registry::new()`.
//!
//! Slice 1e adds the messy-email dev split and the before/after comparison:
//! `AUX_GLINER_EMAILS` is a comma-separated list of extra JSONL files (the
//! `emails-<lang>.jsonl` split). For those cases the report gains, for both the
//! pre-1e registry (`without_email_layer`) and the 1e registry, the union
//! recall, name recall, mask coverage, public-term trap FP and per-pattern
//! person recall, plus the GLiNER-only precision.
//!
//! Run it with the feature on and a local model directory:
//!
//! ```console
//! AUX_GLINER_MODEL_DIR=/path/to/export \
//! AUX_GLINER_ORT_DYLIB=/path/to/libonnxruntime.so \
//! cargo run -p auxesis-kernel-privacy --features ner-gliner --example ner_eval
//! ```
//!
//! Options: `AUX_GLINER_ONNX` (`fp32` | `int8`, default `fp32`),
//! `AUX_GLINER_THRESHOLD` (default `0.4`), `AUX_GLINER_JSON` (write the report
//! to this path as well as stdout), `AUX_GLINER_REPEAT` (timing repetitions,
//! default 3), `AUX_GLINER_EMAILS` (extra JSONL files).

mod corpus;
mod emails;
mod patterns;
mod regions;
mod scoring;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::{EmailLayer, GlinerConfig, GlinerRecognizer, PublicTerms, Registry};
use serde_json::{json, Value};

use crate::corpus::{long_threads, read_cases, read_cases_file, Case};
use crate::emails::email_report;
use crate::patterns::trap_fp;
use crate::regions::{
    after_union, agnostic_name_counts, agnostic_name_recall, as_gold, region_counts,
    region_precision, region_recall, union,
};
use crate::scoring::{lang_map, percentile, score, Score};

fn peak_rss_kb() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn main() {
    let model_dir = std::env::var("AUX_GLINER_MODEL_DIR").expect("AUX_GLINER_MODEL_DIR");
    let int8 = std::env::var("AUX_GLINER_ONNX").as_deref() == Ok("int8");
    let threshold: f32 = std::env::var("AUX_GLINER_THRESHOLD")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.4);
    let repeat: usize = std::env::var("AUX_GLINER_REPEAT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3);

    let repo_root = std::env::var("AUX_REPO_ROOT").unwrap_or_else(|_| ".".to_string());
    let corpus = PathBuf::from(repo_root).join("qa/privacy-eval");
    let cases = read_cases(&corpus);
    let long = long_threads(&cases);
    let public = PublicTerms::from_path(corpus.join("public-terms.json"))
        .unwrap_or_else(|_| PublicTerms::builtin());
    let email_cases: Vec<Case> = std::env::var("AUX_GLINER_EMAILS")
        .ok()
        .map(|list| {
            list.split(',')
                .filter(|path| !path.trim().is_empty())
                .flat_map(|path| read_cases_file(Path::new(path.trim())))
                .collect()
        })
        .unwrap_or_default();

    let mut config = GlinerConfig::new(&model_dir).with_threshold(threshold);
    if int8 {
        config = config.with_int8();
    }
    if let Ok(dylib) = std::env::var("AUX_GLINER_ORT_DYLIB") {
        config = config.with_ort_dylib(dylib);
    }

    let load_start = Instant::now();
    let recognizer = GlinerRecognizer::load(config).expect("load GLiNER");
    let load_s = load_start.elapsed().as_secs_f64();
    let rss_after_load_kb = peak_rss_kb();

    // Warm-up on three short cases, untimed.
    for case in cases.iter().take(3) {
        recognizer.recognize(&case.text).expect("warm-up");
    }

    // One registry with the layer off (pre-1e) and one with it on.
    let before_registry = Registry::builder().with_all().without_email_layer().build();
    let layer = EmailLayer::new();
    let mut per_lang: BTreeMap<String, (Score, Score)> = BTreeMap::new();
    let mut total = (Score::default(), Score::default());
    let mut union_before_total = (Score::default(), Score::default());
    let mut union_after_total = (Score::default(), Score::default());
    let mut long_latency = Vec::new();
    let mut short_latency = Vec::new();
    let mut dropped = 0usize;
    let mut chunks_max = 0usize;
    let mut clean_gold = 0usize;
    let mut union_before_covered = 0usize;
    let mut union_after_covered = 0usize;
    let mut trap_before = 0usize;
    let mut trap_after = 0usize;
    let mut union_before_region = (0usize, 0usize, 0usize, 0usize);
    let mut union_after_region = (0usize, 0usize, 0usize, 0usize);
    let mut union_before_agnostic = (0usize, 0usize);
    let mut union_after_agnostic = (0usize, 0usize);

    let mut long_recall = (Score::default(), Score::default());

    for case in &cases {
        if case.kind == "short" {
            let start = Instant::now();
            for _ in 0..repeat {
                recognizer.recognize(&case.text).expect("recognize");
            }
            short_latency.push(start.elapsed().as_secs_f64() * 1000.0 / repeat as f64);
        }

        let report = recognizer.analyze_report(&case.text).expect("recognize");
        dropped += report.dropped;
        chunks_max = chunks_max.max(report.chunks);
        let predicted = report.spans;
        let predicted_gold = as_gold(&predicted);

        let all = score(&case.gold, &predicted_gold, false);
        let names = score(&case.gold, &predicted_gold, true);
        let entry = per_lang.entry(case.lang.clone()).or_default();
        entry.0.add(&all);
        entry.1.add(&names);
        total.0.add(&all);
        total.1.add(&names);

        let union_before = union(before_registry.analyze(&case.text), &predicted);
        let union_after = after_union(
            &layer,
            before_registry.analyze(&case.text),
            &predicted,
            &case.text,
        );
        union_before_total
            .0
            .add(&score(&case.gold, &union_before, false));
        union_before_total
            .1
            .add(&score(&case.gold, &union_before, true));
        union_after_total
            .0
            .add(&score(&case.gold, &union_after, false));
        union_after_total
            .1
            .add(&score(&case.gold, &union_after, true));
        let before_region = region_counts(&case.gold, &union_before);
        union_before_region.0 += before_region.0;
        union_before_region.1 += before_region.1;
        union_before_region.2 += before_region.2;
        union_before_region.3 += before_region.3;
        let after_region = region_counts(&case.gold, &union_after);
        union_after_region.0 += after_region.0;
        union_after_region.1 += after_region.1;
        union_after_region.2 += after_region.2;
        union_after_region.3 += after_region.3;
        let before_agnostic = agnostic_name_counts(&case.gold, &union_before);
        union_before_agnostic.0 += before_agnostic.0;
        union_before_agnostic.1 += before_agnostic.1;
        let after_agnostic = agnostic_name_counts(&case.gold, &union_after);
        union_after_agnostic.0 += after_agnostic.0;
        union_after_agnostic.1 += after_agnostic.1;
        clean_gold += case.gold.len();
        for gold_span in &case.gold {
            if union_before
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                union_before_covered += 1;
            }
            if union_after
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                union_after_covered += 1;
            }
        }
        trap_before += trap_fp(&union_before, &case.text, &public);
        trap_after += trap_fp(&union_after, &case.text, &public);
    }

    for case in &long {
        let start = Instant::now();
        for _ in 0..repeat {
            recognizer.recognize(&case.text).expect("recognize long");
        }
        long_latency.push(start.elapsed().as_secs_f64() * 1000.0 / repeat as f64);
        let report = recognizer
            .analyze_report(&case.text)
            .expect("recognize long");
        let predicted: Vec<GoldSpan> = report
            .spans
            .iter()
            .map(|span| GoldSpan::new(span.kind, span.start, span.end))
            .collect();
        let all = score(&case.gold, &predicted, false);
        long_recall.0.add(&all);
        let names = score(&case.gold, &predicted, true);
        long_recall.1.add(&names);
    }

    let emails = if email_cases.is_empty() {
        Value::Null
    } else {
        email_report(
            &recognizer,
            &before_registry,
            &Registry::new(),
            &layer,
            &email_cases,
            &public,
        )
    };

    let report = json!({
        "model_dir": model_dir,
        "onnx": if int8 { "model_int8.onnx" } else { "model.onnx" },
        "threshold": threshold,
        "load_s": load_s,
        "rss_after_load_kb": rss_after_load_kb,
        "peak_rss_kb": peak_rss_kb(),
        "dropped_spans": dropped,
        "max_chunks": chunks_max,
        "cases": cases.len(),
        "overall": {
            "recall": total.0.recall(),
            "precision": total.0.precision(),
            "name_recall": total.1.recall(),
            "gold": total.0.gold,
            "predicted": total.0.predicted,
        },
        "per_lang": lang_map(&per_lang),
        "union_before": {
            "recall": union_before_total.0.recall(),
            "precision": union_before_total.0.precision(),
            "name_recall": union_before_total.1.recall(),
            "name_recall_agnostic": agnostic_name_recall(union_before_agnostic),
            "region_precision": region_precision(union_before_region),
            "region_recall": region_recall(union_before_region),
            "mask_coverage": if clean_gold == 0 { 1.0 } else { union_before_covered as f64 / clean_gold as f64 },
            "trap_fp": trap_before,
        },
        "union_after": {
            "recall": union_after_total.0.recall(),
            "precision": union_after_total.0.precision(),
            "name_recall": union_after_total.1.recall(),
            "name_recall_agnostic": agnostic_name_recall(union_after_agnostic),
            "region_precision": region_precision(union_after_region),
            "region_recall": region_recall(union_after_region),
            "mask_coverage": if clean_gold == 0 { 1.0 } else { union_after_covered as f64 / clean_gold as f64 },
            "trap_fp": trap_after,
        },
        "latency_ms": {
            "short_p50": percentile(&mut short_latency.clone(), 0.5),
            "short_p95": percentile(&mut short_latency.clone(), 0.95),
            "long_p50": percentile(&mut long_latency.clone(), 0.5),
            "long_p95": percentile(&mut long_latency.clone(), 0.95),
        },
        "long_thread": {
            "recall": long_recall.0.recall(),
            "name_recall": long_recall.1.recall(),
        },
        "emails": emails,
    });

    let rendered = serde_json::to_string_pretty(&report).expect("serialize");
    if let Ok(path) = std::env::var("AUX_GLINER_JSON") {
        fs::write(path, &rendered).expect("write report");
    }
    println!("{rendered}");
}
