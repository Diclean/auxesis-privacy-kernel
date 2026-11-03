//! The Standard and Deep scorers over the whole corpus.

use std::collections::HashSet;
use std::fs;
use std::time::Instant;

use kernel_privacy::{Anonymizer, PublicTerms, Registry};

use crate::cases::{gold_spans, Case};
use crate::tiers::{is_name, tally_case, DeepMeasure, StandardMeasure};

/// Nearest-rank p95 of a per-case latency list, in milliseconds.
fn p95_ms(mut micros: Vec<u128>) -> u64 {
    if micros.is_empty() {
        return 0;
    }
    micros.sort_unstable();
    let len = micros.len();
    let rank = (len * 95).div_ceil(100).max(1) - 1;
    (micros[rank.min(len - 1)] / 1000) as u64
}

/// Peak resident set size of this process, in MB, from `/proc/self/status`.
///
/// `VmHWM` is the high-water mark, so reading it after the Deep pass is the
/// peak while Deep ran. `None` off Linux, where the table prints NOT MEASURED.
fn peak_rss_mb() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// Score the Standard pipeline: held-out tier recall, trap FPs, latency.
pub(crate) fn measure_standard(
    registry: &Registry,
    cases: &[Case],
    public: &PublicTerms,
    heldout: &HashSet<String>,
) -> StandardMeasure {
    let mut out = StandardMeasure::default();
    let mut latencies_us = Vec::with_capacity(cases.len());
    let mut anonymizer = Anonymizer::new([0x5Au8; 32]);
    for case in cases {
        let start = Instant::now();
        let predicted = registry.analyze(&case.text);
        let _ = anonymizer.anonymize(&case.text, &predicted);
        latencies_us.push(start.elapsed().as_micros());
        for span in &predicted {
            // A name is not a trap: names are clear by design, so a public term
            // read as a name is not a false alarm on the scored classes.
            if is_name(span.kind) || span.start >= span.end {
                continue;
            }
            if let Some(value) = case.text.get(span.start..span.end) {
                if public.contains(value) {
                    out.trap_fp += 1;
                }
            }
        }
        // Names are counted over the whole corpus, not just the held-out split:
        // the row says how many the harness saw, not how many it scored.
        let gold = gold_spans(case);
        out.names += gold.iter().filter(|s| is_name(s.kind)).count() as u64;
        if heldout.contains(&case.id) {
            tally_case((&mut out.c, &mut out.h, &mut out.scored), &gold, &predicted);
        }
    }
    out.p95_ms = p95_ms(latencies_us);
    out
}

/// Score the Deep pipeline: held-out tier recall, trap FPs, latency and memory.
pub(crate) fn measure_deep(
    registry: &Registry,
    cases: &[Case],
    public: &PublicTerms,
    heldout: &HashSet<String>,
) -> DeepMeasure {
    let mut out = DeepMeasure {
        peak_mb: None,
        ..DeepMeasure::default()
    };
    let mut latencies_us = Vec::with_capacity(cases.len());
    let mut anonymizer = Anonymizer::new([0x5Bu8; 32]);
    for case in cases {
        let start = Instant::now();
        let predicted = registry.analyze(&case.text);
        let _ = anonymizer.anonymize(&case.text, &predicted);
        latencies_us.push(start.elapsed().as_micros());
        for span in &predicted {
            if is_name(span.kind) || span.start >= span.end {
                continue;
            }
            if let Some(value) = case.text.get(span.start..span.end) {
                if public.contains(value) {
                    out.trap_fp += 1;
                }
            }
        }
        let gold = gold_spans(case);
        out.names += gold.iter().filter(|s| is_name(s.kind)).count() as u64;
        if heldout.contains(&case.id) {
            tally_case((&mut out.c, &mut out.h, &mut out.scored), &gold, &predicted);
        }
    }
    out.p95_ms = p95_ms(latencies_us);
    out.peak_mb = peak_rss_mb();
    out
}
