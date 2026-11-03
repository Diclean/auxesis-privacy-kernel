//! Tests for the fetch counters.

use kernel_core::WebConfig;
use std::time::{Duration, Instant};

use super::super::*;

#[test]
fn budget_reserves_before_connect_and_caps_each_counter() {
    let config = WebConfig {
        fetches_per_turn: 2,
        fetches_per_day: 3,
        per_host_per_minute: 1,
        ..WebConfig::default()
    };
    let mut budget = WebBudget::new();
    budget.set_day("2026-10-07");
    let now = Instant::now();
    assert!(budget.reserve("a.example", now, &config).is_ok());
    // Same host, same minute: refused by the host cap.
    assert_eq!(
        budget.reserve("a.example", now, &config),
        Err(BudgetKind::Host)
    );
    // A different host fits under the turn cap.
    assert!(budget.reserve("b.example", now, &config).is_ok());
    // Third fetch: turn cap.
    assert_eq!(
        budget.reserve("c.example", now, &config),
        Err(BudgetKind::Turn)
    );
    // A new turn resets the turn counter, and the day cap then binds.
    budget.start_turn();
    assert!(budget.reserve("c.example", now, &config).is_ok());
    assert_eq!(
        budget.reserve("d.example", now, &config),
        Err(BudgetKind::Day)
    );
    // A new day resets the day counter.
    budget.set_day("2026-10-08");
    assert!(budget.reserve("d.example", now, &config).is_ok());
}

#[test]
fn wb_set_day_with_the_same_key_keeps_the_day_counter() {
    let config = WebConfig::default();
    let mut budget = WebBudget::new();
    let now = Instant::now();
    budget.set_day("2026-10-07");
    assert!(budget.reserve("a.example", now, &config).is_ok());
    assert_eq!(budget.day_count(), 1);
    budget.set_day("2026-10-07");
    assert_eq!(budget.day_count(), 1, "the same day key must not reset");
    budget.set_day("2026-10-08");
    assert_eq!(budget.day_count(), 0);
}

#[test]
fn wb_check_projects_all_counters_without_reserving() {
    let now = Instant::now();
    // check() evaluates turn, then day, then host; isolate each projection
    // with a config where only that counter can refuse.
    let host_config = WebConfig {
        fetches_per_turn: 10,
        fetches_per_day: 100,
        per_host_per_minute: 2,
        ..WebConfig::default()
    };
    let mut budget = WebBudget::new();
    assert!(budget.check(&[], now, &host_config).is_ok());
    assert!(budget.reserve("a.example", now, &host_config).is_ok());
    assert!(budget.check(&["b.example"], now, &host_config).is_ok());
    // The same host twice counts twice against the per-host cap.
    assert_eq!(
        budget.check(&["a.example", "a.example"], now, &host_config),
        Err(BudgetKind::Host)
    );
    assert_eq!(budget.turn_count(), 1, "check() must not reserve");

    let day_config = WebConfig {
        fetches_per_turn: 10,
        fetches_per_day: 2,
        per_host_per_minute: 100,
        ..WebConfig::default()
    };
    let mut budget = WebBudget::new();
    assert!(budget.reserve("a.example", now, &day_config).is_ok());
    assert!(budget.check(&["b.example"], now, &day_config).is_ok());
    assert_eq!(
        budget.check(&["b.example", "c.example"], now, &day_config),
        Err(BudgetKind::Day)
    );

    let turn_config = WebConfig {
        fetches_per_turn: 2,
        fetches_per_day: 100,
        per_host_per_minute: 100,
        ..WebConfig::default()
    };
    let mut budget = WebBudget::new();
    assert!(budget.reserve("a.example", now, &turn_config).is_ok());
    assert!(budget.check(&["b.example"], now, &turn_config).is_ok());
    assert_eq!(
        budget.check(&["b.example", "c.example"], now, &turn_config),
        Err(BudgetKind::Turn)
    );
    assert_eq!(budget.turn_count(), 1, "check() must not reserve");
}

#[test]
fn per_host_window_expires_after_a_minute() {
    let config = WebConfig {
        per_host_per_minute: 1,
        ..WebConfig::default()
    };
    let mut budget = WebBudget::new();
    let start = Instant::now();
    assert!(budget.reserve("a.example", start, &config).is_ok());
    assert_eq!(
        budget.reserve("a.example", start + Duration::from_secs(30), &config),
        Err(BudgetKind::Host)
    );
    assert!(budget
        .reserve("a.example", start + Duration::from_secs(61), &config)
        .is_ok());
}
