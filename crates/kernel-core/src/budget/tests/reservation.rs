//! Tests for reservation settlement.

use super::super::*;
use super::support::FakeReservations;

#[test]
fn release_settles_with_zero_usage() {
    let ledger = FakeReservations::default();
    let reservation = Reservation {
        id: 7,
        agent: "main".to_string(),
        day: "2026-10-03".to_string(),
        estimate: UsageTotals {
            tokens_in: 10,
            tokens_out: 4096,
            usd_cents: 0,
        },
        caps: BudgetCaps::default(),
        run_id: None,
    };

    ledger.release(&reservation).unwrap();

    let settled = ledger.settled.borrow();
    assert_eq!(settled.len(), 1);
    assert_eq!(settled[0], UsageActual::default());
}
