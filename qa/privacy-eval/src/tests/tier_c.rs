//! Tests for Tier C measurement, breakdown and miss shapes.

use std::collections::HashSet;

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::{EntityKind, PublicTerms, Registry, Span};

use crate::cases::{gold_spans, Case};
use crate::scoring::measure_standard;
use crate::tier_c::measure::*;
use crate::tier_c::shapes::miss_shape;
use crate::tier_c::*;
use crate::tiers::TierTally;

/// A Russian case sits on its own printed row and costs the scored rows
/// nothing; the old all-language row still counts it, so nothing hides.
#[test]
fn the_out_of_scope_row_prints_and_leaves_the_score() {
    let lines = [
        r#"{"id":"e1","lang":"en","text":"IBAN FR7630006000011234567890189 please","spans":[{"type":"IBAN","start":5,"end":32}]}"#,
        r#"{"id":"r1","lang":"ru","text":"Сегодня погода хорошая.","spans":[{"type":"HEALTH","start":8,"end":14}]}"#,
    ];
    let cases: Vec<Case> = lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("case parses"))
        .collect();
    let ids = HashSet::from(["e1".to_string(), "r1".to_string()]);
    let registry = Registry::new();
    let old = measure_standard(&registry, &cases, &PublicTerms::builtin(), &ids).c;
    let v1: Vec<&Case> = cases.iter().collect();
    let rows = tier_c_rows(&registry, &old, &v1, &cases[..1], None).expect("rows");
    let row = |label: &str| {
        rows.iter()
            .find(|line| line.starts_with(label))
            .unwrap_or_else(|| panic!("no `{label}` row in {rows:#?}"))
            .clone()
    };
    assert!(row("Tier C, v1 out of scope [ru]").ends_with("not scored NOT SCORED gate 0/1"));
    assert!(row("Tier C, held-out-2, gate Private").ends_with("MET 1/1"));
    assert!(row("Tier C, held-out-2, gate Open").ends_with("MET 1/1"));
    assert!(row("Tier C, v1 in scope, gate Private").ends_with("MEASURED 1/1"));
    assert!(row("Tier C, v1 all langs (old row)").ends_with("MISSED 1/2"));
}

#[test]
fn the_private_row_uses_gate_output_even_when_registry_covers() {
    let text = "FR763000";
    let gold = GoldSpan::new(EntityKind::Iban, 0, text.len());
    let predicted = [Span::new(EntityKind::Iban, 0, text.len(), 1.0, "synthetic")];
    let mut paths = TierCPaths::default();
    record_tier_c_gold(
        &mut paths,
        "en",
        text,
        &gold,
        &predicted,
        None,
        Some("⟦IBAN_1⟧"),
    );
    assert_eq!((paths.registry.caught, paths.registry.total), (1, 1));
    assert_eq!((paths.private.caught, paths.private.total), (0, 1));
    assert_eq!((paths.open.caught, paths.open.total), (1, 1));
}

#[test]
fn tier_c_breakdown_counts_are_language_scoped_and_never_render_values() {
    let cases: Vec<Case> = include_str!("../../tests/fixtures/tier-c-breakdown.jsonl")
        .lines()
        .map(|line| serde_json::from_str(line).expect("synthetic case parses"))
        .collect();
    let registry = Registry::new();
    let refs: Vec<&Case> = cases.iter().collect();
    let measured = measure_tier_c(&registry, &refs).expect("synthetic gate measurement");
    let output = tier_c_breakdown(&measured).join("\n");

    assert!(
        output.contains("| IBAN | fr | 1 | 0 | 1 | 1 | 0 | 1 |"),
        "{output}"
    );
    assert!(
        output.contains("| card | en | 1 | 0 | 1 | 1 | 0 | 1 |"),
        "{output}"
    );
    assert!(
        output.contains("| national ID/passport | af | 1 | 1 | 0 | 1 | 1 | 0 |"),
        "{output}"
    );
    assert!(
        output.contains("| health | hu | 1 | 0 | 1 | 1 | 0 | 1 |"),
        "{output}"
    );
    assert!(
        output.contains("| secret | sl | 1 | 1 | 0 | 1 | 1 | 0 |"),
        "{output}"
    );
    assert!(
        output.contains("| IBAN | TOTAL | 1 | 0 | 1 | 1 | 0 | 1 |"),
        "{output}"
    );
    for case in &cases {
        for gold in &case.spans {
            let value = &case.text[gold.start..gold.end];
            assert!(
                !output.contains(value),
                "breakdown rendered fixture value {value}"
            );
        }
        assert!(!output.contains(&case.id), "breakdown rendered fixture id");
        assert!(
            !output.contains(&case.text),
            "breakdown rendered fixture text"
        );
    }
}

#[test]
fn tier_c_miss_shape_renders_only_aggregate_buckets() {
    let cases: Vec<Case> = include_str!("../../tests/fixtures/tier-c-breakdown.jsonl")
        .lines()
        .map(|line| serde_json::from_str(line).expect("synthetic case parses"))
        .collect();
    let mut paths = TierCPaths::default();
    for case in &cases {
        for gold in gold_spans(case) {
            if let Some(class) = tier_c_class(gold.kind) {
                // Synthetic clear output guarantees a miss. Only structural counts are kept.
                for mode in ["Private", "Open"] {
                    miss_shape(&mut paths, mode, class, case, &gold, &[], Some(&case.text));
                }
            }
        }
    }
    let output = tier_c_miss_shape(&paths).join("\n");
    assert!(output.contains("| health | Open | value length | 9-20 chars | 1 |"));
    assert!(output.contains("| health | Private | health phrase | single word | 1 |"));
    assert!(output.contains("| secret | Private | contains digits | yes | 1 |"));
    for case in &cases {
        for gold in &case.spans {
            let value = &case.text[gold.start..gold.end];
            assert!(!output.contains(value), "miss shape rendered fixture value");
        }
        assert!(!output.contains(&case.id), "miss shape rendered fixture id");
        assert!(
            !output.contains(&case.text),
            "miss shape rendered fixture text"
        );
    }
}

#[test]
fn requested_miss_shape_buckets_use_synthetic_health_text() {
    let case = Case {
        id: "synthetic-only".into(),
        lang: "en".into(),
        text: "I take metformin daily for diabetes today.".into(),
        spans: vec![],
    };
    let gold = GoldSpan::new(EntityKind::Health, 7, 16);
    let partial = [Span::new(EntityKind::Health, 9, 13, 1.0, "synthetic")];
    let mut paths = TierCPaths::default();
    miss_shape(
        &mut paths,
        "Private",
        "health",
        &case,
        &gold,
        &partial,
        Some("clear"),
    );
    let rows = tier_c_miss_shape(&paths).join("\n");
    assert!(rows.contains("| health | Private | any lexicon term | yes | 1 |"));
    assert!(rows.contains("| health | Private | personal frame | yes | 1 |"));
    assert!(rows.contains("| health | Private | gold category | medication/dose | 1 |"));
    assert!(rows.contains("| health | Private | sentence length | ≤ 60 chars | 1 |"));
    assert!(rows.contains("| health | Private | span position | start | 1 |"));
    assert!(rows.contains("| health | Private | uncovered remainder | both sides | 1 |"));
    assert!(!rows.contains("synthetic-only") && !rows.contains("metformin"));
}

#[test]
fn russian_and_arabic_language_independent_values_get_an_unscored_row() {
    let lines = [
        r#"{"id":"r1","lang":"ru","text":"IBAN FR7630006000011234567890189","spans":[{"type":"IBAN","start":5,"end":32}]}"#,
        r#"{"id":"a1","lang":"ar","text":"secret sk_live_1234567890123456789012345678901234567890","spans":[{"type":"SECRET","start":7,"end":55}]}"#,
    ];
    let cases: Vec<Case> = lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("synthetic case parses"))
        .collect();
    let rows = tier_c_rows(
        &Registry::new(),
        &TierTally::default(),
        &cases.iter().collect::<Vec<_>>(),
        &[],
        None,
    )
    .expect("synthetic RU/AR v1 cases are reported");
    let row = rows
        .iter()
        .find(|line| line.contains("RU/AR"))
        .expect("RU/AR row");
    assert!(
        row.contains("2 values") && row.contains("NOT SCORED"),
        "{row}"
    );
}
