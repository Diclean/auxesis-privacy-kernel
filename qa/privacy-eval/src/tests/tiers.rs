//! Tests for the tier classification and tallies.

use std::collections::HashSet;

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::{EntityKind, PublicTerms, Registry, Span};

use crate::cases::Case;
use crate::scoring::measure_standard;
use crate::table::*;
use crate::tiers::*;

/// An empty tally used to read `100.00 %` and pass its bar. A missed name
/// costs no recall; a missed e-mail costs a point of it. The denominator is
/// never empty: an e-mail hit beside a missed name reads 100 %, the same
/// case with the e-mail missed reads 0 %, a name alone measures nothing.
#[test]
fn an_empty_tally_is_never_a_pass_and_a_name_costs_no_recall() {
    assert_eq!(hundredths(0, 0), None);
    assert_eq!(rate_cell(0, 0), NO_RATE);
    let line = row_line(
        "Tier C recall",
        &rate_cell(0, 0),
        ">= 99.5 %",
        "NOT MEASURED",
    );
    assert!(line.ends_with(">= 99.5 %  NOT MEASURED"), "{line}");
    assert!(!line.contains("MET"), "{line}");

    let name = GoldSpan::new(EntityKind::Person, 0, 9);
    let email = GoldSpan::new(EntityKind::Email, 11, 27);
    let hit = [Span::new(EntityKind::Email, 11, 27, 1.0, "test")];
    let clean = score(&[name, email], &hit, 1);
    assert_eq!(clean.names, 1, "the name is still reported");
    assert_eq!(
        clean.scored.hundredths(),
        Some(10000),
        "a name costs nothing"
    );
    assert_eq!(
        (clean.c.total, clean.h.total),
        (0, 0),
        "no bar takes a name"
    );
    assert_eq!(score(&[name, email], &[], 1).scored.hundredths(), Some(0));
    assert_eq!(score(&[name], &[], 1).scored.hundredths(), None);
}

/// Score one case's gold with these predictions, as `measure_standard` does.
fn score(gold: &[GoldSpan], predicted: &[Span], names: u64) -> StandardMeasure {
    let mut out = StandardMeasure {
        names,
        ..StandardMeasure::default()
    };
    tally_case((&mut out.c, &mut out.h, &mut out.scored), gold, predicted);
    out
}

/// The same through the real Standard scorer over a real case, so the
/// policy is not only proven against `tally_case`.
#[test]
fn a_name_alone_leaves_the_held_out_scored_tally_empty() {
    let json = r#"{"id":"n1","lang":"en","text":"Bob Smith wrote it.","spans":[{"type":"PERSON","start":0,"end":9}]}"#;
    let cases: Vec<Case> = vec![serde_json::from_str(json).expect("case parses")];
    let out = measure_standard(
        &Registry::new(),
        &cases,
        &PublicTerms::builtin(),
        &HashSet::from(["n1".to_string()]),
    );
    assert_eq!(out.names, 1);
    assert_eq!(out.scored.hundredths(), None, "nothing to score");
    assert_eq!(out.c.hundredths(), None, "Tier C has no denominator");
    assert_eq!(out.h.hundredths(), None, "Tier H has no denominator");
}

/// Tier C claims exactly the kernel's prohibited set -- the five classes
/// the owner requires hidden -- Tier H the model-emitted non-names, and
/// every other scored class reaches no bar.
#[test]
fn a_tier_bar_reaches_only_its_own_classes() {
    let want = |kind: EntityKind, tier: Option<Tier>| {
        assert_eq!(scored_tier(kind), tier, "{kind:?}");
    };
    for kind in [
        EntityKind::Iban,
        EntityKind::CreditCard,
        EntityKind::NationalId,
    ] {
        want(kind, Some(Tier::C));
    }
    for kind in [EntityKind::Address, EntityKind::DateOfBirth] {
        want(kind, Some(Tier::H));
    }
    for kind in [EntityKind::Email, EntityKind::Phone, EntityKind::Person] {
        want(kind, None);
    }
}

#[test]
fn tiers_follow_the_kernel_classification() {
    assert_eq!(tier_of(EntityKind::Email), Tier::C);
    assert_eq!(tier_of(EntityKind::Iban), Tier::C);
    assert_eq!(tier_of(EntityKind::NationalId), Tier::C);
    // Names are their own tier, and that tier is never scored.
    assert_eq!(tier_of(EntityKind::Organization), Tier::Name);
    assert_eq!(tier_of(EntityKind::Health), Tier::C9);
    assert_eq!(tier_of(EntityKind::Religion), Tier::C9);
    assert_eq!(tier_of(EntityKind::SexualOrientation), Tier::C9);
    assert_eq!(tier_of(EntityKind::Union), Tier::C9);
    assert_eq!(tier_of(EntityKind::Ethnicity), Tier::C9);
    assert_eq!(tier_of(EntityKind::Secret), Tier::N);
}
