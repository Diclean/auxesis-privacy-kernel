//! Test helpers shared by the budget test modules.

use std::cell::RefCell;

use super::super::*;

#[derive(Default)]
pub(super) struct FakeLedger {
    pub(super) totals: UsageTotals,
    pub(super) calls: RefCell<Vec<(String, String)>>,
    pub(super) fail: Option<String>,
}

impl FakeLedger {
    pub(super) fn with(totals: UsageTotals) -> Self {
        Self {
            totals,
            ..Self::default()
        }
    }
}

impl UsageLedger for FakeLedger {
    fn day_totals(&self, agent: &str, day: &str) -> Result<UsageTotals, BudgetError> {
        self.calls
            .borrow_mut()
            .push((agent.to_string(), day.to_string()));
        match &self.fail {
            Some(message) => Err(BudgetError::Ledger(message.clone())),
            None => Ok(self.totals),
        }
    }
}

#[derive(Default)]
pub(super) struct FakeAudit {
    pub(super) events: RefCell<Vec<(String, String)>>,
    pub(super) fail: bool,
}

impl AuditSink for FakeAudit {
    fn audit(&self, kind: &str, payload: &str) -> Result<(), BudgetError> {
        if self.fail {
            return Err(BudgetError::Audit("disk full".to_string()));
        }
        self.events
            .borrow_mut()
            .push((kind.to_string(), payload.to_string()));
        Ok(())
    }
}

pub(super) fn caps(
    tokens_in: Option<u64>,
    tokens_out: Option<u64>,
    usd_cents: Option<u64>,
) -> BudgetCaps {
    BudgetCaps {
        tokens_in,
        tokens_out,
        usd_cents,
        connector_calls: None,
        unlimited: false,
    }
}

/// Minimal reservation ledger that records settles.
#[derive(Default)]
pub(super) struct FakeReservations {
    pub(super) settled: RefCell<Vec<UsageActual>>,
}

impl ReservationLedger for FakeReservations {
    fn try_reserve(
        &self,
        agent: &str,
        day: &str,
        caps: &BudgetCaps,
        estimate: &UsageTotals,
    ) -> Result<ReserveOutcome, BudgetError> {
        Ok(ReserveOutcome::Reserved(Reservation {
            id: 1,
            agent: agent.to_string(),
            day: day.to_string(),
            estimate: *estimate,
            caps: *caps,
            run_id: None,
        }))
    }

    fn settle(&self, _reservation: &Reservation, actual: &UsageActual) -> Result<(), BudgetError> {
        self.settled.borrow_mut().push(*actual);
        Ok(())
    }
}
