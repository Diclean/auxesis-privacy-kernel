//! Tier C through the registry and the production gate, and its rows.

use std::collections::{BTreeMap, BTreeSet};

use kernel_privacy::EntityKind;

use crate::cases::IN_SCOPE_LANGS;
use crate::classes::report_class;
use crate::gate::Outcome;
use crate::table::{rate_cell, NO_RATE};
use crate::tiers::{scored_tier, OutcomeTally, Tier, TierTally};

pub(crate) mod measure;
pub(crate) mod shapes;

/// Tier C over one set of cases, through the three paths.
#[derive(Default)]
pub(crate) struct TierCPaths {
    pub(crate) registry: TierTally,
    pub(crate) private: TierTally,
    pub(crate) open: TierTally,
    /// Class -> `[n, missed in Private, missed in Open]`.
    pub(crate) misses: BTreeMap<&'static str, [u64; 3]>,
    /// `(class, language) -> [Private hits, Private misses, Open hits, Open misses]`.
    pub(crate) by_class_language: BTreeMap<(&'static str, String), [u64; 4]>,
    /// (class, mode, feature, bucket) -> misses; keys contain no case data.
    pub(crate) miss_shape: BTreeMap<(&'static str, &'static str, &'static str, &'static str), u64>,
    /// E-mail, phone, address: always hidden in Private, kept in Open by design.
    pub(crate) contact: TierTally,
    pub(crate) langs: BTreeSet<String>,
    /// Class -> `[n, Standard registry, gate Private, gate Open, registry hit
    /// left clear in Private, in Open]` (GATE-REGISTRY-GAP-1). Counts only.
    pub(crate) gap: BTreeMap<&'static str, [u64; 6]>,
    /// Class -> what the gate did with each value, Private and Open. A partial
    /// mask is in `leaked`; see [`OutcomeTally`].
    pub(crate) private_outcomes: BTreeMap<&'static str, OutcomeTally>,
    pub(crate) open_outcomes: BTreeMap<&'static str, OutcomeTally>,
    /// Every Tier C value, both modes.
    pub(crate) private_outcome_total: OutcomeTally,
    pub(crate) open_outcome_total: OutcomeTally,
}

impl TierCPaths {
    pub(crate) fn add_gold(
        &mut self,
        kind: EntityKind,
        lang: &str,
        registry_hit: bool,
        private_hidden: bool,
        open_hidden: bool,
    ) {
        self.registry.add(registry_hit);
        self.private.add(private_hidden);
        self.open.add(open_hidden);
        if let Some(class) = report_class(kind) {
            let row = self.misses.entry(class).or_insert([0; 3]);
            row[0] += 1;
            row[1] += u64::from(!private_hidden);
            row[2] += u64::from(!open_hidden);
        }
        if let Some(class) = tier_c_class(kind) {
            let row = self
                .by_class_language
                .entry((class, lang.to_owned()))
                .or_insert([0; 4]);
            row[usize::from(!private_hidden)] += 1;
            row[2 + usize::from(!open_hidden)] += 1;
        }
    }

    /// Record one Tier C value's gate outcome in both modes. A value outside
    /// Tier C is ignored: this split exists only for the classes with the bar.
    pub(crate) fn add_outcome(&mut self, kind: EntityKind, private: Outcome, open: Outcome) {
        if scored_tier(kind) != Some(Tier::C) {
            return;
        }
        self.private_outcome_total.add(private);
        self.open_outcome_total.add(open);
        if let Some(class) = tier_c_class(kind) {
            self.private_outcomes.entry(class).or_default().add(private);
            self.open_outcomes.entry(class).or_default().add(open);
        }
    }
}

/// The five public Tier C categories, kept in display order.
pub(crate) const TIER_C_CLASSES: [&str; 5] =
    ["IBAN", "card", "national ID/passport", "health", "secret"];

pub(crate) fn tier_c_class(kind: EntityKind) -> Option<&'static str> {
    match kind {
        EntityKind::Iban => Some("IBAN"),
        EntityKind::CreditCard => Some("card"),
        EntityKind::NationalId
        | EntityKind::PassportMrz
        | EntityKind::FrNir
        | EntityKind::HuTaj
        | EntityKind::HuTaxId
        | EntityKind::ZaId
        | EntityKind::UkNino => Some("national ID/passport"),
        EntityKind::Health => Some("health"),
        EntityKind::Secret => Some("secret"),
        _ => None,
    }
}

pub(crate) fn tier_c_breakdown(paths: &TierCPaths) -> Vec<String> {
    let mut lines = vec![
        "| class | language | Private n | hit | miss | Open n | hit | miss |".to_owned(),
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |".to_owned(),
    ];
    for class in TIER_C_CLASSES {
        let mut totals = [0u64; 4];
        for lang in IN_SCOPE_LANGS {
            let [pm, p_miss, om, o_miss] = paths
                .by_class_language
                .get(&(class, lang.to_owned()))
                .copied()
                .unwrap_or([0; 4]);
            totals[0] += pm + p_miss;
            totals[1] += pm;
            totals[2] += om + o_miss;
            totals[3] += om;
            lines.push(format!(
                "| {class} | {lang} | {} | {pm} | {p_miss} | {} | {om} | {o_miss} |",
                pm + p_miss,
                om + o_miss,
            ));
        }
        lines.push(format!(
            "| {class} | TOTAL | {} | {} | {} | {} | {} | {} |",
            totals[0],
            totals[1],
            totals[0] - totals[1],
            totals[2],
            totals[3],
            totals[2] - totals[3]
        ));
    }
    lines
}

/// The Tier C outcome split: per class and in total, Private and Open.
///
/// Counts and percentages only, never a value or a case text. `blocked` is a
/// gate refusal; `leaked` includes a partial mask, because the 6-character run
/// is the only read test the scorer has and cannot tell a half mask from a
/// full leak.
pub(crate) fn tier_c_outcome_split(paths: &TierCPaths) -> Vec<String> {
    let mut lines = vec![
        "held-out-2 Tier C outcome split (counts only; partial masks count in leaked):".to_owned(),
        "| class | mode | n | masked | leaked | blocked |".to_owned(),
        "| --- | --- | ---: | ---: | ---: | ---: |".to_owned(),
    ];
    let row = |class: &str, mode: &str, tally: OutcomeTally| {
        let n = tally.total();
        format!(
            "| {class} | {mode} | {n} | {} | {} | {} |",
            split_cell(tally.masked, n),
            split_cell(tally.leaked, n),
            split_cell(tally.blocked, n),
        )
    };
    for class in TIER_C_CLASSES {
        let private = paths
            .private_outcomes
            .get(class)
            .copied()
            .unwrap_or_default();
        let open = paths.open_outcomes.get(class).copied().unwrap_or_default();
        lines.push(row(class, "Private", private));
        lines.push(row(class, "Open", open));
    }
    lines.push(row("all", "Private", paths.private_outcome_total));
    lines.push(row("all", "Open", paths.open_outcome_total));
    lines
}

/// `count (xx.xx %)` of `total`, or the no-rate cell when nothing was measured.
fn split_cell(count: u64, total: u64) -> String {
    if total == 0 {
        NO_RATE.to_string()
    } else {
        format!("{count} ({})", rate_cell(count, total))
    }
}

pub(crate) fn tier_c_miss_shape(paths: &TierCPaths) -> Vec<String> {
    let mut lines = vec![
        "held-out-2 Tier C miss shape (counts only):".to_owned(),
        "| class | mode | feature | bucket | misses |".to_owned(),
        "| --- | --- | --- | --- | ---: |".to_owned(),
    ];
    for ((class, mode, feature, bucket), count) in &paths.miss_shape {
        if *count > 0 {
            lines.push(format!(
                "| {class} | {mode} | {feature} | {bucket} | {count} |"
            ));
        }
    }
    lines
}
