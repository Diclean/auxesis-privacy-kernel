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
