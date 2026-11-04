//! The advisory pre-call guard over a day's recorded usage.

use super::caps::Budgets;
use super::denial::{audit_denial, Decision, Denial, DenialReason};
use super::ledger::{AuditSink, UsageLedger};
use super::usage::UsageKind;

/// Enforces per-agent daily caps before provider calls.
///
/// `check` is deliberately synchronous: callers run it immediately before a
/// provider call, and a denial is audited as `budget.denied` before it is
/// returned. Ledger failures fail closed (deny) — an unreadable meter must
/// never turn into an unbounded spend.
///
/// This is the advisory, non-atomic path: between `check` and the actual
/// spend a concurrent turn can pass the same check, so N racing callers can
/// each spend after one shared check. The engine uses [`ReservationLedger`](super::reservation::ReservationLedger)
/// (atomic reserve-then-settle, own reserve included) instead; `check`
/// remains for callers that only need a read-only verdict.
///
/// Caps are enforced *between* calls: an agent just below its cap can still
/// make one call that crosses it. There is no bound on how far a single
/// call can cross the cap here — only [`ReservationLedger`](super::reservation::ReservationLedger) can bound the
/// output side, by passing the admitted reservation as the provider's
/// completion cap and latching the day closed on a crossing settle.
pub struct BudgetGuard<'a> {
    budgets: &'a Budgets,
    ledger: &'a dyn UsageLedger,
    audit: &'a dyn AuditSink,
    day: &'a str,
}

impl<'a> BudgetGuard<'a> {
    /// Build a guard for one local day.
    pub fn new(
        budgets: &'a Budgets,
        ledger: &'a dyn UsageLedger,
        audit: &'a dyn AuditSink,
        day: &'a str,
    ) -> Self {
        Self {
            budgets,
            ledger,
            audit,
            day,
        }
    }

    /// Decide whether `agent` may run. Denials are audited before returning.
    ///
    /// Only an explicit `unlimited = true` enforces nothing and allows
    /// without touching the ledger; absent or zero fields fall back to the
    /// conservative per-kind defaults.
    pub fn check(&self, agent: &str) -> Decision {
        let caps = self.budgets.caps_for(agent);
        if caps.is_unlimited() {
            return Decision::Allowed;
        }

        let totals = match self.ledger.day_totals(agent, self.day) {
            Ok(totals) => totals,
            Err(err) => {
                return self.deny(Denial {
                    agent: agent.to_string(),
                    day: self.day.to_string(),
                    reason: DenialReason::LedgerUnavailable {
                        message: err.to_string(),
                    },
                    audit_error: None,
                });
            }
        };

        // Provider kinds only: `ConnectorCalls` is metered by the connector
        // layer and is not carried by `UsageTotals`, so a connector cap can
        // never deny a provider call here.
        for kind in UsageKind::PROVIDER {
            let Some(limit) = caps.limit(kind) else {
                continue;
            };
            let spent = totals.get(kind);
            if spent >= limit {
                return self.deny(Denial {
                    agent: agent.to_string(),
                    day: self.day.to_string(),
                    reason: DenialReason::CapExceeded {
                        kind,
                        spent,
                        reserved: 0,
                        limit,
                    },
                    audit_error: None,
                });
            }
        }

        Decision::Allowed
    }

    /// Audit the denial and return it. An audit failure never un-denies.
    fn deny(&self, denial: Denial) -> Decision {
        Decision::Denied(audit_denial(self.audit, denial))
    }
}
