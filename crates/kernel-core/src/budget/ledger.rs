//! The usage-ledger and audit ports the guard talks to.

use thiserror::Error;

use super::usage::UsageTotals;

/// Failures reported by a [`UsageLedger`] or an [`AuditSink`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BudgetError {
    /// The day's usage could not be read; the guard fails closed.
    #[error("usage ledger unavailable: {0}")]
    Ledger(String),
    /// The denial could not be audited; the denial still stands.
    #[error("audit sink unavailable: {0}")]
    Audit(String),
}

/// Day totals for an agent, as seen by the guard. The app implements this trait.
pub trait UsageLedger {
    /// Total spend for `agent` on the local day `day` (`YYYY-MM-DD`).
    fn day_totals(&self, agent: &str, day: &str) -> Result<UsageTotals, BudgetError>;
}

/// Destination for `budget.denied` audit events.
pub trait AuditSink {
    /// Append an audit event with a JSON payload.
    fn audit(&self, kind: &str, payload: &str) -> Result<(), BudgetError>;
}
