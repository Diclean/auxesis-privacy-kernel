//! Measuring Tier C through the gate and building its rows.

use std::sync::Arc;

use kernel_privacy::eval::GoldSpan;

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
#[cfg(feature = "ner-gliner")]
use kernel_privacy::NameDictionary;
use kernel_privacy::{EntityKind, Gate, Registry, Span};

use crate::cases::{gold_spans, in_scope, Case};
use crate::gate::{gate_hides, outcome, Outcome};
use crate::heldout::validate_heldout_2_scope;
use crate::table::{measured_line, rate_cell, row_line, BAR_C};
use crate::tiers::{covered, scored_tier, Tier, TierTally};

use super::shapes::miss_shape;
use super::{
    tier_c_breakdown, tier_c_class, tier_c_miss_shape, tier_c_outcome_split, TierCPaths,
    TIER_C_CLASSES,
};

pub(crate) fn record_tier_c_gold(
    paths: &mut TierCPaths,
    lang: &str,
    text: &str,
    gold: &GoldSpan,
    predicted: &[Span],
    private_issued: Option<&str>,
    open_issued: Option<&str>,
) {
    let private = outcome(text, gold, private_issued);
    let open = outcome(text, gold, open_issued);
    paths.add_gold(
        gold.kind,
        lang,
        covered(predicted, gold),
        private == Outcome::Masked,
        open == Outcome::Masked,
    );
    paths.add_outcome(gold.kind, private, open);
}

/// Score `cases` through the Registry and the gate in both modes. A gate
/// refusal counts as a miss: Private tokenises, it never blocks.
pub(crate) fn measure_tier_c(registry: &Registry, cases: &[&Case]) -> Result<TierCPaths, String> {
    measure_tier_c_gated(registry, cases, None)
}

fn measure_tier_c_gated(
    registry: &Registry,
    cases: &[&Case],
    deep: Option<&Arc<Registry>>,
) -> Result<TierCPaths, String> {
    let context = Context {
        destination: Destination::Vendor("privacy-eval".into()),
    };
    let gate = |mode| {
        let Decision::Allow(grant) = admit(PathId::A1, mode, &context) else {
            return Err(format!("the A1 {mode:?} grant was not admitted"));
        };
        #[cfg(feature = "ner-gliner")]
        if let Some(deep) = deep {
            return Ok(Gate::for_grant_with_deep_detector(
                &grant,
                [0x2Cu8; 32],
                Arc::new(
                    NameDictionary::new(std::iter::empty::<&str>()).map_err(|e| e.to_string())?,
                ),
                Arc::clone(deep) as Arc<dyn kernel_privacy::safetext::Detector>,
            ));
        }
        let _ = deep;
        Ok(Gate::for_grant(&grant, [0x2Cu8; 32]))
    };
    let (mut private, mut open) = (gate(PrivacyMode::Private)?, gate(PrivacyMode::Open)?);
    // The registry the Standard gate runs: `registry` is the Deep one when the
    // model is installed, so the gap line compares like with like.
    let standard = Registry::new();
    let mut out = TierCPaths::default();
    for case in cases {
        out.langs.insert(case.lang.clone());
        let predicted = registry.analyze(&case.text);
        let standard_predicted = standard.analyze(&case.text);
        let issued_p = private
            .text(&case.text)
            .ok()
            .map(|(s, _)| s.as_str().to_string());
        let issued_o = open
            .text(&case.text)
            .ok()
            .map(|(s, _)| s.as_str().to_string());
        for gold in gold_spans(case) {
            let hidden = |issued: &Option<String>| gate_hides(&case.text, &gold, issued.as_deref());
            if scored_tier(gold.kind) != Some(Tier::C) {
                if matches!(
                    gold.kind,
                    EntityKind::Email | EntityKind::Phone | EntityKind::Address
                ) {
                    out.contact.add(hidden(&issued_p));
                }
                continue;
            }
            record_tier_c_gold(
                &mut out,
                &case.lang,
                &case.text,
                &gold,
                &predicted,
                issued_p.as_deref(),
                issued_o.as_deref(),
            );
            if let Some(class) = tier_c_class(gold.kind) {
                let found = covered(&standard_predicted, &gold);
                let p = gate_hides(&case.text, &gold, issued_p.as_deref());
                let o = gate_hides(&case.text, &gold, issued_o.as_deref());
                let row = out.gap.entry(class).or_insert([0; 6]);
                for (cell, hit) in row
                    .iter_mut()
                    .zip([true, found, p, o, found && !p, found && !o])
                {
                    *cell += u64::from(hit);
                }
                if !p {
                    miss_shape(
                        &mut out,
                        "Private",
                        class,
                        case,
                        &gold,
                        &predicted,
                        issued_p.as_deref(),
                    );
                }
                if !o {
                    miss_shape(
                        &mut out,
                        "Open",
                        class,
                        case,
                        &gold,
                        &predicted,
                        issued_o.as_deref(),
                    );
                }
            }
        }
    }
    Ok(out)
}

/// The Tier C block. The bar rows are held-out-2 through the gate; then the
/// Registry; then the v1 split: its old all-language row (`old`, the tally the
/// table always printed), its in-scope rows, and its out-of-scope languages on
/// a row that is printed and never scored.
pub(crate) fn tier_c_rows(
    registry: &Registry,
    old: &TierTally,
    v1: &[&Case],
    v2: &[Case],
    deep: Option<&Arc<Registry>>,
) -> Result<Vec<String>, String> {
    validate_heldout_2_scope(v2)?;
    let v2: Vec<&Case> = v2.iter().collect();
    let (v1_in, v1_out): (Vec<&Case>, Vec<&Case>) =
        v1.iter().partition(|case| in_scope(&case.lang));
    let new = measure_tier_c(registry, &v2)?;
    let deep_new = deep
        .map(|detector| measure_tier_c_gated(registry, &v2, Some(detector)))
        .transpose()?;
    let inside = measure_tier_c(registry, &v1_in)?;
    let outside = measure_tier_c(registry, &v1_out)?;
    let per_class = new
        .misses
        .iter()
        .map(|(class, [n, p, o])| format!("{class} {p}/{o} of {n}"))
        .collect::<Vec<_>>()
        .join(", ");
    let out_langs = outside.langs.iter().cloned().collect::<Vec<_>>().join(",");
    let independent = out_of_scope_independent_count(v1_out.iter().copied());
    let o = &outside.private;
    let mut rows = vec![
        measured_line("Tier C, held-out-2, gate Private", &new.private, BAR_C),
        measured_line("Tier C, held-out-2, gate Open", &new.open, BAR_C),
        measured_line("Tier C, held-out-2, Registry", &new.registry, None),
        format!("  held-out-2 misses (Private/Open of n): {per_class}"),
        measured_line("  e-mail/phone/address, h-o-2, Private", &new.contact, None),
    ];
    for class in TIER_C_CLASSES {
        let [n, found, p, o, lost_p, lost_o] = new.gap.get(class).copied().unwrap_or([0; 6]);
        rows.push(format!(
            "  held-out-2 {class}: registry {found} / gate {p} Private, {o} Open \
             (Standard, of {n}); registry-found left clear: {lost_p} Private, {lost_o} Open"
        ));
    }
    rows.push("held-out-2 Tier C gate breakdown (counts only):".to_owned());
    for (label, tally) in [
        (
            "Tier C, held-out-2, gate Private Deep",
            deep_new.as_ref().map(|m| &m.private),
        ),
        (
            "Tier C, held-out-2, gate Open Deep",
            deep_new.as_ref().map(|m| &m.open),
        ),
    ] {
        rows.push(tally.map_or_else(
            || format!("{label}: NOT MEASURED"),
            |t| measured_line(label, t, None),
        ));
    }
    rows.extend(tier_c_breakdown(&new));
    rows.extend(tier_c_outcome_split(&new));
    rows.extend(tier_c_miss_shape(&new));
    rows.extend([
        measured_line("Tier C, v1 all langs (old row), Registry", old, BAR_C),
        measured_line("Tier C, v1 in scope, gate Private", &inside.private, None),
        measured_line("Tier C, v1 in scope, gate Open", &inside.open, None),
        measured_line("Tier C, v1 in scope, Registry", &inside.registry, None),
        "v1 in-scope Tier C gate breakdown (counts only):".to_owned(),
    ]);
    rows.extend(tier_c_breakdown(&inside));
    rows.extend([
        row_line(
            &format!("Tier C, v1 out of scope [{out_langs}]"),
            &rate_cell(o.caught, o.total),
            "not scored",
            &format!("NOT SCORED gate {}/{}", o.caught, o.total),
        ),
        row_line(
            "Tier C, v1 RU/AR IBAN/card/ID/secret",
            &format!("{independent} values"),
            "not scored",
            "NOT SCORED",
        ),
    ]);
    Ok(rows)
}

fn out_of_scope_independent_count<'a>(cases: impl IntoIterator<Item = &'a Case>) -> usize {
    cases
        .into_iter()
        .filter(|case| matches!(case.lang.as_str(), "ru" | "ar"))
        .flat_map(gold_spans)
        .filter(|gold| {
            matches!(
                gold.kind,
                EntityKind::Iban
                    | EntityKind::CreditCard
                    | EntityKind::NationalId
                    | EntityKind::PassportMrz
                    | EntityKind::Secret
            )
        })
        .count()
}
