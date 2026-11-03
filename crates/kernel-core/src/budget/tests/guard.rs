//! Tests for the pre-call budget guard.

use std::collections::HashMap;

use super::super::*;
use super::support::{caps, FakeAudit, FakeLedger};

#[test]
fn spends_below_every_cap_are_allowed() {
    let ledger = FakeLedger::with(UsageTotals {
        tokens_in: 99,
        tokens_out: 9,
        usd_cents: 4,
    });
    let audit = FakeAudit::default();
    let budgets = Budgets {
        default: caps(Some(100), Some(10), Some(5)),
        ..Budgets::default()
    };

    let decision = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03").check("main");

    assert!(decision.is_allowed(), "{decision:?}");
    assert_eq!(
        ledger.calls.borrow().as_slice(),
        [("main".to_string(), "2026-10-03".to_string())]
    );
    assert!(audit.events.borrow().is_empty());
}

#[test]
fn reaching_a_cap_denies_and_audits() {
    let ledger = FakeLedger::with(UsageTotals {
        tokens_in: 1200,
        ..UsageTotals::default()
    });
    let audit = FakeAudit::default();
    let budgets = Budgets {
        default: caps(Some(1000), None, None),
        ..Budgets::default()
    };

    let decision = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03").check("main");

    let denial = decision.denial().expect("must be denied");
    assert_eq!(
        denial.reason,
        DenialReason::CapExceeded {
            kind: UsageKind::TokensIn,
            spent: 1200,
            reserved: 0,
            limit: 1000,
        }
    );
    assert!(denial.reason_text().contains("tokens_in"));
    assert!(denial.reason_text().contains("1200/1000"));

    let events = audit.events.borrow();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "budget.denied");
    assert!(events[0].1.contains(r#""agent":"main""#), "{}", events[0].1);
    assert!(events[0].1.contains(r#""kind":"tokens_in""#));
    assert!(events[0].1.contains(r#""spent":1200"#));
    assert!(events[0].1.contains(r#""limit":1000"#));
    assert!(events[0].1.contains(r#""day":"2026-10-03""#));
}

#[test]
fn checks_kinds_in_order_and_reports_the_first_reached_cap() {
    let ledger = FakeLedger::with(UsageTotals {
        tokens_in: 10,
        tokens_out: 20,
        usd_cents: 30,
    });
    let audit = FakeAudit::default();
    let budgets = Budgets {
        default: caps(Some(10), Some(20), Some(30)),
        ..Budgets::default()
    };

    let decision = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03").check("main");
    assert_eq!(
        decision.denial().unwrap().reason,
        DenialReason::CapExceeded {
            kind: UsageKind::TokensIn,
            spent: 10,
            reserved: 0,
            limit: 10,
        }
    );
}

#[test]
fn per_agent_caps_are_isolated() {
    let ledger = FakeLedger::with(UsageTotals {
        tokens_in: 1000,
        ..UsageTotals::default()
    });
    let audit = FakeAudit::default();
    // `main` has an explicit cap; `axis` is explicitly unlimited (the
    // only way to opt out now that an empty set enforces defaults).
    let mut budgets = Budgets {
        default: caps(None, None, None),
        agents: HashMap::new(),
    };
    budgets
        .agents
        .insert("main".to_string(), caps(Some(1000), None, None));
    budgets.agents.insert(
        "axis".to_string(),
        BudgetCaps {
            unlimited: true,
            ..BudgetCaps::default()
        },
    );

    // `main` is maxed out, `axis` has no cap at all.
    let guard = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03");
    assert!(guard.check("main").denial().is_some());
    assert!(guard.check("axis").is_allowed());
    assert_eq!(
        ledger.calls.borrow().as_slice(),
        [("main".to_string(), "2026-10-03".to_string())],
        "the uncapped agent is never queried"
    );
}

#[test]
fn a_failing_ledger_fails_closed_and_audits() {
    let ledger = FakeLedger {
        fail: Some("database is locked".to_string()),
        ..FakeLedger::default()
    };
    let audit = FakeAudit::default();
    let budgets = Budgets {
        default: caps(Some(1), None, None),
        ..Budgets::default()
    };

    let decision = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03").check("main");

    let denial = decision.denial().expect("fail closed");
    assert_eq!(
        denial.reason,
        DenialReason::LedgerUnavailable {
            message: "usage ledger unavailable: database is locked".to_string(),
        }
    );
    assert!(denial.reason_text().contains("failing closed"));
    let events = audit.events.borrow();
    assert_eq!(events.len(), 1);
    assert!(events[0].1.contains("database is locked"));
}

#[test]
fn a_failing_audit_does_not_un_deny() {
    let ledger = FakeLedger::with(UsageTotals {
        tokens_in: 5,
        ..UsageTotals::default()
    });
    let audit = FakeAudit {
        fail: true,
        ..FakeAudit::default()
    };
    let budgets = Budgets {
        default: caps(Some(5), None, None),
        ..Budgets::default()
    };

    let decision = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03").check("main");

    let denial = decision.denial().expect("still denied");
    assert_eq!(
        denial.audit_error.as_deref(),
        Some("audit sink unavailable: disk full")
    );
    assert!(denial.reason_text().contains("audit failed"));
    assert!(denial.audit_payload().contains("audit failed"));
}

#[test]
fn an_exhausted_connector_cap_never_gates_a_provider_call() {
    // The whole point of splitting PROVIDER from ALL: an agent that has hit
    // its connector-call cap must still be able to make an ordinary
    // provider call (its token budget is a different dimension).
    let caps = BudgetCaps {
        tokens_in: Some(1000),
        connector_calls: Some(1),
        ..BudgetCaps::default()
    };
    assert_eq!(caps.limit(UsageKind::ConnectorCalls), Some(1));

    let ledger = FakeLedger::with(UsageTotals {
        tokens_in: 10,
        ..UsageTotals::default()
    });
    let audit = FakeAudit::default();
    let mut budgets = Budgets::default();
    budgets.agents.insert("main".to_string(), caps);
    let decision = BudgetGuard::new(&budgets, &ledger, &audit, "2026-10-03").check("main");
    assert!(
        decision.is_allowed(),
        "the connector cap is not a provider cap: {decision:?}"
    );
    assert!(
        audit.events.borrow().is_empty(),
        "no provider denial may be audited for a connector dimension"
    );
}
