//! The over-mask budget on normal prose and the release timing bars.

use kernel_privacy::Registry;

use super::common;

/// Normal prose per language (one sentence per line), with no health content.
const PROSE: [(&str, &str); 3] = [
    (
        "hu",
        include_str!("../../../../qa/privacy-eval/prose/hu.txt"),
    ),
    (
        "af",
        include_str!("../../../../qa/privacy-eval/prose/af.txt"),
    ),
    (
        "sl",
        include_str!("../../../../qa/privacy-eval/prose/sl.txt"),
    ),
];

/// Whether a span comes from the K10 recognisers. The e-mail layer's name
/// heuristic (`email_layer_*`) also tags sentence-initial words in prose; that
/// behaviour predates K10 and is measured apart by the eval harness.
fn k10_span(span: &kernel_privacy::Span) -> bool {
    matches!(span.recognizer, "sensitive_terms" | "secrets")
}

#[test]
fn normal_prose_is_over_masked_in_at_most_one_percent_of_lines() {
    let registry = Registry::new();
    for (lang, prose) in PROSE {
        let lines: Vec<&str> = prose
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(lines.len(), 100, "{lang} corpus is not 100 lines");
        let over: Vec<&str> = lines
            .iter()
            .copied()
            .filter(|line| registry.analyze(line).iter().any(k10_span))
            .collect();
        assert!(
            over.len() * 100 <= lines.len(),
            "{lang}: {} of {} lines over-masked: {over:?}",
            over.len(),
            lines.len()
        );
    }
}

/// The Standard registry on one megabyte of mixed prose, health text and keys.
/// Release timing only: `cargo test --release -- --ignored --nocapture`.
#[test]
#[ignore = "release timing: run with --release --ignored --nocapture"]
fn one_megabyte_of_mixed_text_analyses_in_bounded_time() {
    let unit = "Elle a une consultation le 12 mars, sa tension est normale. Le patient souffre de diabète et prend de l'insuline. Contact: 138-1234-5678, token sk-proj-FAKEKEY0123456789abcdefGHIJKL. Ana je kupila raketo. 他有糖尿病。\n";
    let text = unit.repeat(1_000_000 / unit.len() + 1);
    let registry = Registry::new();
    let spans = registry.analyze(&text);
    // The fastest of nine runs, after one warm-up: the budget is on the work,
    // not on the scheduler.
    let elapsed = common::fastest(|| {
        let _ = registry.analyze(&text);
    });
    eprintln!(
        "PERF analyze {} bytes -> {} spans in {:?}",
        text.len(),
        spans.len(),
        elapsed
    );
    assert!(!spans.is_empty());
    assert!(elapsed < linear_budget(), "one megabyte took {elapsed:?}");
}

/// One megabyte of each input that the wrap join once walked quadratically.
/// Release timing, run in the gate: `cargo test --release -- --ignored`.
#[test]
#[ignore = "release timing: run with --release --ignored"]
fn wrapped_key_inputs_of_one_megabyte_are_linear() {
    let mut task_list = String::new();
    let mut n = 0usize;
    while task_list.len() < 1_000_000 {
        n += 1;
        task_list.push_str(&format!("task-{}\n", n % 10));
    }
    let inputs = [
        ("sk-a lines", "sk-a\n".repeat(200_000)),
        ("AKIA lines", "AKIA\n".repeat(200_000)),
        ("task lines", task_list),
    ];
    let registry = Registry::new();
    for (name, text) in inputs {
        let spans = registry.analyze(&text);
        // The fastest of nine runs, after one warm-up: the bar is on the
        // work, not on the scheduler.
        let elapsed = common::fastest(|| {
            let _ = registry.analyze(&text);
        });
        eprintln!(
            "PERF {name}: {} bytes, {} spans, {elapsed:?}",
            text.len(),
            spans.len()
        );
        assert!(
            elapsed.as_secs_f64() < 2.0,
            "{name}: one megabyte took {elapsed:?}"
        );
    }
}

/// The linear-time bar: 10 s in release; the debug profile is slower, so it
/// gets 30 s. What is checked does not change (see secrets_in_prose_are_found.rs).
fn linear_budget() -> std::time::Duration {
    if cfg!(debug_assertions) {
        std::time::Duration::from_secs(30)
    } else {
        std::time::Duration::from_secs(10)
    }
}
