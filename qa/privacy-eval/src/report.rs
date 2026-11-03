//! The detection table, the in-repo report and the K10/HU/prose rows.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use kernel_core::privacy::PrivacyMode;
use kernel_privacy::{EntityKind, PublicTerms, Registry};

use crate::cases::{gold_spans, Case, IN_SCOPE_LANGS};
use crate::classes::{class_table, measure_mode, print_known_contacts};
use crate::deep::load_deep;
use crate::heldout::{load_heldout, parse_heldout_2};
use crate::private_sets::{self, HeldOut, HELDOUT_1, HELDOUT_2};
use crate::scoring::{measure_deep, measure_standard};
use crate::table::{
    measured_row, print_row, rate_cell, BAR_H_DEEP_HUNDREDTHS, BAR_H_STANDARD_HUNDREDTHS,
    BAR_LATENCY_DEEP_MS, BAR_LATENCY_STANDARD_MS, BAR_PEAK_MEMORY_MB, BAR_TRAP_FP,
};
use crate::tier_c::measure::tier_c_rows;
use crate::tiers::{covered, TierTally};

/// The known-contacts slice: dictionary, text and the names it must mask.
const KNOWN_CONTACTS: &str = "qa/privacy-eval/known_contacts.jsonl";

/// The commit under test, or `"unknown"`.
fn git_commit() -> String {
    if let Ok(value) = env::var("PRIVACY_EVAL_COMMIT") {
        let value = value.trim();
        if !value.is_empty() {
            return value.to_string();
        }
    }
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The detection table: held-out tier recall, trap FPs, p95 latency and memory.
pub(crate) fn run_table(cases: &[Case], public: &PublicTerms) -> Result<ExitCode, String> {
    let dir = private_sets::eval_dir()?;
    let (held_1, held_2) = match (
        private_sets::load(&dir, HELDOUT_1)?,
        private_sets::load(&dir, HELDOUT_2)?,
    ) {
        (HeldOut::Present(one), HeldOut::Present(two)) => (one, two),
        (one, two) => {
            for set in [one, two] {
                if let HeldOut::Absent(path) = set {
                    println!(
                        "held-out set absent, skipped: {} (set AUXESIS_EVAL_DIR)",
                        path.display()
                    );
                }
            }
            println!("held-out table: SKIPPED, held-out bars not measured");
            print_in_repo(cases, None)?;
            return Ok(ExitCode::SUCCESS);
        }
    };
    let heldout = load_heldout(&held_1);
    let held_out_cases = cases
        .iter()
        .filter(|case| heldout.contains(&case.id))
        .count();

    let standard = Registry::new();
    let standard_measure = measure_standard(&standard, cases, public, &heldout);

    let deep = match load_deep() {
        Ok(registry) => Some(registry),
        Err(reason) => {
            if env::var("PRIVACY_EVAL_DEBUG").is_ok_and(|value| value != "0") {
                eprintln!("privacy-eval: deep detection not measured: {reason}");
            }
            None
        }
    };
    let deep_measure = deep
        .as_deref()
        .map(|registry| measure_deep(registry, cases, public, &heldout));

    // Rows without a Standard/Deep qualifier report the detection level in
    // force: the production pipeline (Standard plus Deep) when the model is
    // present, Standard alone otherwise.
    let registry = deep.as_deref().unwrap_or(&standard);
    let c = deep_measure
        .as_ref()
        .map_or(&standard_measure.c, |measure| &measure.c);
    let (hash_2, cases_2) = parse_heldout_2(&held_2)?;
    let v1: Vec<&Case> = cases
        .iter()
        .filter(|case| heldout.contains(&case.id))
        .collect();

    print_row("measure", "value", "bar", "status");
    for line in tier_c_rows(registry, c, &v1, &cases_2, deep.as_ref())? {
        println!("{line}");
    }
    let deep_score = deep_measure.as_ref().map(|m| (&m.scored, m.names));
    let (scored, names) = deep_score.unwrap_or((&standard_measure.scored, standard_measure.names));
    measured_row("Scored recall, held-out, names excluded", scored, None);
    measured_row(
        "Tier H recall, held-out, Standard",
        &standard_measure.h,
        Some((">= 95 %", BAR_H_STANDARD_HUNDREDTHS)),
    );
    match &deep_measure {
        Some(measure) => measured_row(
            "Tier H recall, held-out, Deep",
            &measure.h,
            Some((">= 98 %", BAR_H_DEEP_HUNDREDTHS)),
        ),
        None => print_row(
            "Tier H recall, held-out, Deep",
            "n/a",
            ">= 98 %",
            "NOT MEASURED",
        ),
    }
    // Names are reported and never scored (EVAL-NO-NAMES).
    let seen = names;
    print_row(
        "names (not hidden by design)",
        &seen.to_string(),
        "no bar",
        &format!("{seen} seen"),
    );
    let trap_fp = deep_measure
        .as_ref()
        .map_or(standard_measure.trap_fp, |measure| measure.trap_fp);
    print_row(
        "False positives on trap cases",
        &trap_fp.to_string(),
        "<= 40",
        if trap_fp <= BAR_TRAP_FP {
            "MET"
        } else {
            "MISSED"
        },
    );
    let standard_ms = standard_measure.p95_ms;
    print_row(
        "Latency p95, Standard",
        &format!("{standard_ms} ms"),
        "<= 150 ms",
        if standard_ms <= BAR_LATENCY_STANDARD_MS {
            "MET"
        } else {
            "MISSED"
        },
    );
    match &deep_measure {
        Some(measure) => {
            let deep_ms = measure.p95_ms;
            print_row(
                "Latency p95, Deep detection",
                &format!("{deep_ms} ms"),
                "<= 400 ms",
                if deep_ms <= BAR_LATENCY_DEEP_MS {
                    "MET"
                } else {
                    "MISSED"
                },
            );
            match measure.peak_mb {
                Some(mb) => print_row(
                    "Peak memory, Deep detection",
                    &format!("{mb} MB"),
                    "<= 1 GB",
                    if mb <= BAR_PEAK_MEMORY_MB {
                        "MET"
                    } else {
                        "MISSED"
                    },
                ),
                None => print_row(
                    "Peak memory, Deep detection",
                    "n/a",
                    "<= 1 GB",
                    "NOT MEASURED",
                ),
            }
        }
        None => {
            print_row(
                "Latency p95, Deep detection",
                "n/a",
                "<= 400 ms",
                "NOT MEASURED",
            );
            print_row(
                "Peak memory, Deep detection",
                "n/a",
                "<= 1 GB",
                "NOT MEASURED",
            );
        }
    }
    print_in_repo(cases, Some(held_out_cases))?;
    println!(
        "held-out-2: {} cases, sha256 {hash_2} (verified), Tier C scored on [{}]",
        cases_2.len(),
        IN_SCOPE_LANGS.join(",")
    );
    Ok(ExitCode::SUCCESS)
}

/// The in-repo report: per-class table over the whole corpus, then the known
/// contacts, K10, prose and HU checks. It reads no held-out file, so CI can
/// run it on a checkout alone.
fn print_in_repo(cases: &[Case], held_out_cases: Option<usize>) -> Result<(), String> {
    let private = measure_mode(cases, PrivacyMode::Private, "Private")?;
    let open = measure_mode(cases, PrivacyMode::Open, "Open")?;
    println!("\nper-class over the whole in-repo corpus (not the held-out split):");
    print!("{}", class_table(&private, &open));
    print_known_contacts(Path::new(KNOWN_CONTACTS));
    print_k10(cases);
    print_prose();
    print_hu_check(cases);
    let languages: BTreeSet<&str> = cases.iter().map(|case| case.lang.as_str()).collect();
    let held_out = held_out_cases.map_or_else(|| "set absent".to_owned(), |n| format!("{n} cases"));
    println!(
        "corpus: {} cases, held-out {}, langs [{}], commit {}",
        cases.len(),
        held_out,
        languages.into_iter().collect::<Vec<_>>().join(","),
        git_commit()
    );
    Ok(())
}

/// The K10 rows: the Standard recall of the fictional `k10-` cases, grouped by
/// the four kinds K10 adds, and the spans the over-masking guards (`k10-neg-`)
/// produced. The rows have no bar and are not held-out: the counts print, and a
/// guard that masks anything prints `MISSED`.
fn print_k10(cases: &[Case]) {
    let registry = Registry::new();
    let mut groups: BTreeMap<&'static str, TierTally> = BTreeMap::new();
    let (mut guard_spans, mut guard_cases) = (0u64, 0u64);
    for case in cases.iter().filter(|case| case.id.starts_with("k10-")) {
        let predicted = registry.analyze(&case.text);
        if case.id.starts_with("k10-neg-") {
            guard_cases += 1;
            guard_spans += predicted.len() as u64;
            continue;
        }
        for gold in gold_spans(case) {
            let group = match gold.kind {
                EntityKind::Health => "K10 health terms",
                EntityKind::Religion
                | EntityKind::SexualOrientation
                | EntityKind::Union
                | EntityKind::Ethnicity => "K10 Art. 9 other categories",
                EntityKind::Phone => "K10 phone, Chinese mobile",
                EntityKind::Secret => "K10 API keys and tokens",
                _ => continue,
            };
            groups
                .entry(group)
                .or_default()
                .add(covered(&predicted, &gold));
        }
    }
    for (measure, tally) in &groups {
        print_row(
            measure,
            &rate_cell(tally.caught, tally.total),
            "no bar",
            &format!("MEASURED {}/{}", tally.caught, tally.total),
        );
    }
    let status = if guard_spans == 0 { "MET" } else { "MISSED" };
    print_row(
        "K10 over-mask guards",
        &format!("{guard_spans}"),
        "0 spans",
        &format!("{status}, {guard_cases} cases"),
    );
}

/// The Hungarian over-mask check: the share of the HU cases (e-mail threads and
/// short texts, ids `hu-…`) that hold a K10 span outside every gold span. Bar: at
/// most 0.5 %. A span counts as false when it overlaps no gold span.
fn print_hu_check(cases: &[Case]) {
    let registry = Registry::new();
    let (mut total, mut over) = (0u64, 0u64);
    for case in cases.iter().filter(|case| case.id.starts_with("hu-")) {
        total += 1;
        let golds = gold_spans(case);
        let false_k10 = registry.analyze(&case.text).iter().any(|span| {
            matches!(span.recognizer, "sensitive_terms" | "secrets")
                && !golds
                    .iter()
                    .any(|gold| span.start < gold.end && gold.start < span.end)
        });
        if false_k10 {
            over += 1;
        }
    }
    let status = if total == 0 {
        "NOT MEASURED"
    } else if over * 200 <= total {
        "MET"
    } else {
        "MISSED"
    };
    print_row(
        "Over-mask, HU e-mail and short cases",
        &rate_cell(over, total),
        "<= 0.5 %",
        &format!("{status} {over}/{total}"),
    );
}

/// The normal-prose rows: the share of prose lines the K10 recognisers mask (bar:
/// at most 1 %), and the share any recogniser masks. The second row includes the
/// e-mail layer's name heuristic, which predates K10 and has no bar.
fn print_prose() {
    let registry = Registry::new();
    for lang in ["hu", "af", "sl"] {
        let upper = lang.to_uppercase();
        let path = format!("qa/privacy-eval/prose/{lang}.txt");
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("privacy-eval: prose {path} not measured: {error}");
                print_row(
                    &format!("Over-mask, normal prose {upper}"),
                    "n/a",
                    "<= 1 %",
                    "NOT MEASURED",
                );
                continue;
            }
        };
        let (mut k10_lines, mut any_lines, mut total) = (0u64, 0u64, 0u64);
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let spans = registry.analyze(line);
            total += 1;
            if spans
                .iter()
                .any(|span| matches!(span.recognizer, "sensitive_terms" | "secrets"))
            {
                k10_lines += 1;
            }
            if !spans.is_empty() {
                any_lines += 1;
            }
        }
        let status = if total == 0 {
            "NOT MEASURED"
        } else if k10_lines * 100 <= total {
            "MET"
        } else {
            "MISSED"
        };
        print_row(
            &format!("Over-mask, normal prose {upper}"),
            &rate_cell(k10_lines, total),
            "<= 1 %",
            &format!("{status} {k10_lines}/{total}"),
        );
        print_row(
            &format!("Any span, prose {upper} (incl. e-mail)"),
            &rate_cell(any_lines, total),
            "no bar",
            &format!("MEASURED {any_lines}/{total}"),
        );
    }
}
