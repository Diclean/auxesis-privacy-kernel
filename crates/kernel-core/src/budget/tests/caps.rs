//! Tests for daily caps and their defaults.

use std::collections::HashMap;

use super::super::limits::conservative_limit;
use super::super::*;
use super::support::{caps, FakeAudit, FakeLedger};

#[test]
fn caps_for_merges_default_and_agent_overrides() {
    let mut budgets = Budgets {
        default: caps(Some(100), Some(50), None),
        agents: HashMap::new(),
    };
    budgets
        .agents
        .insert("main".to_string(), caps(Some(5), None, Some(7)));

    assert_eq!(budgets.caps_for("main"), caps(Some(5), Some(50), Some(7)));
    assert_eq!(budgets.caps_for("axis"), caps(Some(100), Some(50), None));
    // A bare `Budgets` now carries the conservative defaults (E-17); only
    // an explicit `unlimited = true` turns caps off.
    assert!(!Budgets::default().is_unset());
    assert_eq!(
        Budgets::default().caps_for("main"),
        BudgetCaps::conservative_default()
    );
    assert!(!budgets.is_unset());
}

#[test]
fn default_budgets_cap_every_agent() {
    let budgets = Budgets::default();
    let caps = budgets.caps_for("anything");
    assert!(!caps.is_unset(), "a fresh install must be capped");
    assert_eq!(
        caps.limit(UsageKind::TokensIn),
        Some(DEFAULT_DAILY_TOKENS_IN)
    );
    assert_eq!(
        caps.limit(UsageKind::TokensOut),
        Some(DEFAULT_DAILY_TOKENS_OUT)
    );
    assert_eq!(
        caps.limit(UsageKind::UsdCents),
        Some(DEFAULT_DAILY_USD_CENTS)
    );
    assert!(!budgets.is_unset());

    // The default is enforced before any provider call: a day already at
    // the default cap is denied (and audited).
    let ledger = FakeLedger::with(UsageTotals {
        tokens_in: DEFAULT_DAILY_TOKENS_IN,
        ..UsageTotals::default()
    });
    let audit = FakeAudit::default();
    let decision = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03").check("main");
    assert!(
        decision.denial().is_some(),
        "the fresh default must deny, got {decision:?}"
    );
    assert_eq!(audit.events.borrow().len(), 1, "the denial is audited");
}

#[test]
fn calibration_values_are_pinned_and_the_machinery_still_holds() {
    // H-03: only the VALUES changed (owner decision, daily use);
    // reservation, latch, warning and the `unlimited` opt-out are
    // unchanged. This test pins both.
    assert_eq!(DEFAULT_DAILY_TOKENS_IN, 2_000_000);
    assert_eq!(DEFAULT_DAILY_TOKENS_OUT, 400_000);
    assert_eq!(DEFAULT_DAILY_USD_CENTS, 500);

    let budgets = Budgets::default();
    let caps = budgets.caps_for("main");
    assert_eq!(caps.limit(UsageKind::TokensIn), Some(2_000_000));
    assert_eq!(caps.limit(UsageKind::TokensOut), Some(400_000));
    assert_eq!(caps.limit(UsageKind::UsdCents), Some(500));

    // Warning still fires at 80% of the new cap.
    assert_eq!(warning_threshold(2_000_000), 1_600_000);
    assert_eq!(warning_threshold(500), 400);

    // The day still latches closed at the cap (spend exactly on it denies).
    let ledger = FakeLedger::with(UsageTotals {
        tokens_out: 400_000,
        ..UsageTotals::default()
    });
    let audit = FakeAudit::default();
    let decision = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03").check("main");
    assert_eq!(
        decision.denial().unwrap().reason,
        DenialReason::CapExceeded {
            kind: UsageKind::TokensOut,
            spent: 400_000,
            reserved: 0,
            limit: 400_000,
        }
    );

    // Just below the new caps is allowed: the raise must not break the
    // admission path.
    let ledger = FakeLedger::with(UsageTotals {
        tokens_in: 1_999_999,
        tokens_out: 399_999,
        usd_cents: 499,
    });
    let audit = FakeAudit::default();
    assert!(BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03")
        .check("main")
        .is_allowed());

    // `unlimited` remains the only way to remove the caps.
    let mut opted_out = Budgets::default();
    opted_out.default.unlimited = true;
    for kind in UsageKind::ALL {
        assert_eq!(opted_out.caps_for("main").limit(kind), None);
    }
}

#[test]
fn unlimited_needs_an_explicit_opt_in_and_disables_the_caps() {
    let opted_out: Budgets = toml::from_str("[default]\nunlimited = true\n").unwrap();
    assert!(opted_out.default.unlimited);
    let caps = opted_out.caps_for("main");
    assert!(caps.is_unlimited());
    for kind in UsageKind::ALL {
        assert_eq!(caps.limit(kind), None, "unlimited means no limit");
    }

    // A fresh config is *not* opted out.
    assert!(!Budgets::default().caps_for("main").is_unlimited());
    // And the opt-out survives merging (an override cannot re-cap it).
    assert!(BudgetCaps::conservative_default()
        .merged_with(&opted_out.default)
        .is_unlimited());
}

#[test]
fn unlimited_is_the_only_uncapped_path() {
    let ledger = FakeLedger::default();
    let audit = FakeAudit::default();
    // An explicit `unlimited = true` is the only way to reach the
    // ledger-free fast path; an empty cap set now enforces the
    // conservative defaults (P1-1).
    let budgets = Budgets {
        default: BudgetCaps {
            unlimited: true,
            ..BudgetCaps::default()
        },
        agents: HashMap::new(),
    };

    let decision = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03").check("main");

    assert!(decision.is_allowed());
    assert!(ledger.calls.borrow().is_empty(), "ledger must not be read");
    assert!(audit.events.borrow().is_empty(), "nothing to audit");

    // The empty set is *not* unlimited: its limits are the defaults.
    let empty = Budgets {
        default: BudgetCaps::default(),
        agents: HashMap::new(),
    };
    assert!(!empty.caps_for("main").is_unlimited());
    assert_eq!(
        Budgets::default()
            .caps_for("main")
            .limit(UsageKind::TokensIn),
        Some(DEFAULT_DAILY_TOKENS_IN)
    );
}

#[test]
fn an_empty_or_partial_cap_set_enforces_the_conservative_defaults() {
    // P1-1 migration shape: every pre-slice config carries an empty
    // `[budgets.default]` table. `serde(default)` does not fire for a
    // present-but-empty table, so the effective limits are resolved per
    // field here — and they are the conservative ones.
    let budgets: Budgets = toml::from_str(
        r#"
            [default]
            [agents.axis]
            tokens_in = 10
            "#,
    )
    .unwrap();
    assert!(budgets.default.is_unset(), "raw fields stay absent");
    let main = budgets.caps_for("main");
    assert!(
        !main.is_unlimited(),
        "an empty table must not read as `unlimited`"
    );
    for kind in UsageKind::ALL {
        assert_eq!(
            main.limit(kind),
            Some(conservative_limit(kind)),
            "{kind} must fall back to the conservative default"
        );
    }
    // A per-agent override only replaces the field it names; the rest still
    // fall back to the defaults.
    assert_eq!(
        budgets.caps_for("axis").limit(UsageKind::TokensIn),
        Some(10)
    );
    assert_eq!(
        budgets.caps_for("axis").limit(UsageKind::TokensOut),
        Some(DEFAULT_DAILY_TOKENS_OUT)
    );
    assert!(!budgets.caps_for("axis").is_unlimited());
}

#[test]
fn a_zero_placeholder_falls_back_to_the_conservative_default() {
    // `tokens_in = 0` is the other way an old config (or a template)
    // means "no opinion": it must not disable the cap.
    let budgets = Budgets {
        default: caps(Some(0), None, None),
        ..Budgets::default()
    };
    assert_eq!(
        budgets.caps_for("main").limit(UsageKind::TokensIn),
        Some(DEFAULT_DAILY_TOKENS_IN)
    );

    let ledger = FakeLedger::with(UsageTotals {
        tokens_in: DEFAULT_DAILY_TOKENS_IN,
        ..UsageTotals::default()
    });
    let audit = FakeAudit::default();
    let decision = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03").check("main");
    assert!(
        decision.denial().is_some(),
        "a zero placeholder must not mean `deny everything`"
    );
}

#[test]
fn limit_honours_unlimited_even_with_values_present() {
    // M11: deleting the `unlimited` short-circuit in `limit()` must fail
    // this test — the opt-out gates real configured numbers, not only an
    // all-unset set.
    let caps = BudgetCaps {
        tokens_in: Some(5),
        tokens_out: Some(5),
        usd_cents: Some(5),
        connector_calls: Some(5),
        unlimited: true,
    };
    for kind in UsageKind::ALL {
        assert_eq!(caps.limit(kind), None, "unlimited removes {kind}");
    }

    let ledger = FakeLedger::with(UsageTotals {
        tokens_in: u64::MAX / 2,
        tokens_out: u64::MAX / 2,
        usd_cents: u64::MAX / 2,
    });
    let audit = FakeAudit::default();
    let budgets = Budgets {
        default: caps,
        agents: HashMap::new(),
    };
    assert!(BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03")
        .check("main")
        .is_allowed());
    assert!(ledger.calls.borrow().is_empty());
}

#[test]
fn an_old_config_with_an_empty_budgets_table_still_denies_at_the_default() {
    // The exact bytes a pre-E-17 install carries: the table header with
    // no fields under it. The guard must deny once the default day is
    // spent (probe p1: 1,000,000 tokens_in was admitted before the fix;
    // H-03 raised the value but the empty table is still capped).
    let budgets: Budgets = toml::from_str("[default]\n").unwrap();
    let ledger = FakeLedger::with(UsageTotals {
        tokens_in: DEFAULT_DAILY_TOKENS_IN,
        ..UsageTotals::default()
    });
    let audit = FakeAudit::default();
    let decision = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03").check("main");
    let denial = decision
        .denial()
        .expect("an upgraded install must still be capped");
    assert_eq!(
        denial.reason,
        DenialReason::CapExceeded {
            kind: UsageKind::TokensIn,
            spent: DEFAULT_DAILY_TOKENS_IN,
            reserved: 0,
            limit: DEFAULT_DAILY_TOKENS_IN,
        }
    );
    assert_eq!(audit.events.borrow().len(), 1);
}

#[test]
fn per_agent_zero_falls_back_per_field() {
    // An agent override with a zero placeholder keeps the field's default
    // while inheriting the other fields.
    let mut budgets = Budgets {
        default: caps(Some(1000), Some(100), Some(10)),
        ..Budgets::default()
    };
    budgets
        .agents
        .insert("main".to_string(), caps(Some(0), None, None));
    let caps = budgets.caps_for("main");
    assert_eq!(
        caps.limit(UsageKind::TokensIn),
        Some(DEFAULT_DAILY_TOKENS_IN)
    );
    assert_eq!(caps.limit(UsageKind::TokensOut), Some(100));
    assert_eq!(caps.limit(UsageKind::UsdCents), Some(10));
}

#[test]
fn caps_round_trip_keeps_the_other_three_kinds_intact() {
    let caps = BudgetCaps {
        tokens_in: Some(11),
        tokens_out: Some(22),
        usd_cents: Some(33),
        connector_calls: Some(44),
        unlimited: false,
    };
    let text = toml::to_string(&caps).unwrap();
    let back: BudgetCaps = toml::from_str(&text).unwrap();
    assert_eq!(back, caps, "all four kinds survive a round-trip");
    assert_eq!(back.tokens_in, Some(11));
    assert_eq!(back.tokens_out, Some(22));
    assert_eq!(back.usd_cents, Some(33));
    assert_eq!(back.connector_calls, Some(44));

    // An unset connector cap adds no key to a serialized config: a fresh
    // install's config.toml stays byte-shape unchanged.
    let fresh = BudgetCaps::conservative_default();
    assert!(fresh.connector_calls.is_none());
    assert!(!toml::to_string(&fresh).unwrap().contains("connector_calls"));
    // ...but its effective cap is still the conservative default.
    assert_eq!(
        fresh.limit(UsageKind::ConnectorCalls),
        Some(DEFAULT_DAILY_CONNECTOR_CALLS)
    );
    let zero = BudgetCaps {
        connector_calls: Some(0),
        ..BudgetCaps::conservative_default()
    };
    assert_eq!(
        zero.limit(UsageKind::ConnectorCalls),
        Some(DEFAULT_DAILY_CONNECTOR_CALLS),
        "a zero placeholder must not mean `deny every connector call`"
    );
}

#[test]
fn connector_caps_merge_field_by_field() {
    let defaults = BudgetCaps {
        tokens_in: Some(10),
        connector_calls: Some(5),
        ..BudgetCaps::default()
    };
    let overrides = BudgetCaps {
        connector_calls: Some(9),
        ..BudgetCaps::default()
    };
    let merged = defaults.merged_with(&overrides);
    assert_eq!(merged.tokens_in, Some(10), "the other kinds are intact");
    assert_eq!(merged.connector_calls, Some(9));
    assert_eq!(
        BudgetCaps::default().limit(UsageKind::ConnectorCalls),
        Some(DEFAULT_DAILY_CONNECTOR_CALLS)
    );
}
