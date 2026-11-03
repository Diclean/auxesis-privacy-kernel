//! Per-agent daily budgets over recorded provider usage.
//!
//! Usage is recorded by resource dimension ([`UsageKind`]: input tokens,
//! output tokens, cents) in the store; [`Budgets`] carries the daily caps
//! from the `[budgets]` section of `config.toml`; and [`BudgetGuard`]
//! decides — before a provider call — whether an agent may spend more today.
//!
//! The guard never touches the store directly: it talks to a
//! [`UsageLedger`] for the day's totals and an [`AuditSink`] for the
//! `budget.denied` events. The app implements both over its own store, which
//! keeps this crate dependency-free of SQLite and trivial to test with
//! in-memory fakes.
//!
//! Configuration shape (top-level caps apply to every agent, `[budgets.agents.*]`
//! overrides field by field). Unknown keys are rejected so a typo like
//! `token_in` can never silently disable a cap:
//!
//! ```toml
//! [budgets.default]
//! tokens_in = 2_000_000
//! tokens_out = 400_000
//! usd_cents = 500
//!
//! [budgets.agents.main]
//! tokens_in = 20_000
//! ```
//!
//! When `[budgets]` is absent — or the `[budgets.default]` table exists but
//! is empty, or a field is absent/zero — the conservative defaults apply per
//! field: a fresh **and an upgraded** install is capped, not unlimited. An
//! explicit `unlimited = true` is the only opt-out (the daemon logs it
//! loudly on every turn).

mod caps;
mod denial;
mod guard;
mod ledger;
mod limits;
mod prices;
mod reservation;
mod usage;

pub use caps::{BudgetCaps, Budgets};
pub use denial::{audit_denial, Decision, Denial, DenialReason};
pub use guard::BudgetGuard;
pub use ledger::{AuditSink, BudgetError, UsageLedger};
pub use limits::{
    warning_threshold, DEFAULT_DAILY_CONNECTOR_CALLS, DEFAULT_DAILY_TOKENS_IN,
    DEFAULT_DAILY_TOKENS_OUT, DEFAULT_DAILY_USD_CENTS, ESTIMATED_UNIT, WARNING_DENOMINATOR,
    WARNING_NUMERATOR,
};
pub use prices::{ModelPrice, PriceTable};
pub use reservation::{
    Reservation, ReservationLedger, ReserveOutcome, UsageActual, RESERVATION_TTL,
};
pub use usage::{UsageKind, UsageTotals};

#[cfg(test)]
mod tests;
