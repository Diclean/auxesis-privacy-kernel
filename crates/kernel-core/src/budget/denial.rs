//! The denial vocabulary, its audit payload and the check outcome.

use super::ledger::AuditSink;
use super::usage::UsageKind;

/// Why the guard denied a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// A daily cap is reached (or exceeded).
    CapExceeded {
        /// The capped resource.
        kind: UsageKind,
        /// Spend recorded so far today.
        spent: u64,
        /// Spend reserved by calls still in flight today.
        reserved: u64,
        /// Configured daily cap.
        limit: u64,
    },
    /// Usage could not be read, so the guard failed closed.
    LedgerUnavailable {
        /// Underlying ledger error.
        message: String,
    },
    /// A completed call reached or crossed a daily cap, so the day is latched
    /// closed: every later call for this agent/day is denied until the next
    /// local day. Written by
    /// [`ReservationLedger::settle`](super::reservation::ReservationLedger::settle)
    /// when a provider
    /// settles above its admitted reservation.
    FailClosed {
        /// Why the day was closed (which kind reached its cap, and where).
        message: String,
    },
}

/// One denial, with enough context for the user and the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// Agent the call was made for.
    pub agent: String,
    /// Local day the budget applies to (`YYYY-MM-DD`).
    pub day: String,
    /// Structured cause.
    pub reason: DenialReason,
    /// Set when writing the `budget.denied` audit event failed.
    pub audit_error: Option<String>,
}

impl Denial {
    /// Human-readable one-liner.
    pub fn reason_text(&self) -> String {
        let base = match &self.reason {
            DenialReason::CapExceeded {
                kind,
                spent,
                reserved,
                limit,
            } => {
                if *reserved > 0 {
                    format!(
                        "agent `{}` reached its daily {kind} budget \
                         ({spent} spent + {reserved} reserved / {limit} on {})",
                        self.agent, self.day
                    )
                } else {
                    format!(
                        "agent `{}` reached its daily {kind} budget ({spent}/{limit} on {})",
                        self.agent, self.day
                    )
                }
            }
            DenialReason::LedgerUnavailable { message } => format!(
                "agent `{}`: cannot verify the daily budget ({message}); failing closed",
                self.agent
            ),
            DenialReason::FailClosed { message } => format!(
                "agent `{}`: {message}; failing closed for the rest of {}",
                self.agent, self.day
            ),
        };
        match &self.audit_error {
            Some(err) => format!("{base} (audit failed: {err})"),
            None => base,
        }
    }

    /// JSON payload written to the store as a `budget.denied` event.
    pub fn audit_payload(&self) -> String {
        let mut payload = serde_json::json!({
            "agent": self.agent,
            "day": self.day,
            "reason": self.reason_text(),
        });
        match &self.reason {
            DenialReason::CapExceeded {
                kind,
                spent,
                reserved,
                limit,
            } => {
                payload["kind"] = serde_json::json!(kind.as_str());
                payload["spent"] = serde_json::json!(spent);
                payload["reserved"] = serde_json::json!(reserved);
                payload["limit"] = serde_json::json!(limit);
            }
            DenialReason::LedgerUnavailable { message } => {
                payload["error"] = serde_json::json!(message);
            }
            DenialReason::FailClosed { message } => {
                payload["fail_closed"] = serde_json::json!(true);
                payload["message"] = serde_json::json!(message);
            }
        }
        payload.to_string()
    }
}

/// Outcome of a budget check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The agent is within its daily caps.
    Allowed,
    /// The agent must not make another provider call today.
    Denied(Denial),
}

impl Decision {
    /// True for [`Decision::Allowed`].
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allowed)
    }

    /// The denial, when there is one.
    pub fn denial(&self) -> Option<&Denial> {
        match self {
            Decision::Allowed => None,
            Decision::Denied(denial) => Some(denial),
        }
    }
}

/// Audit a denial and return it, recording an audit failure on the denial
/// instead of un-denying the call.
pub fn audit_denial(audit: &dyn AuditSink, mut denial: Denial) -> Denial {
    if let Err(err) = audit.audit("budget.denied", &denial.audit_payload()) {
        denial.audit_error = Some(err.to_string());
    }
    denial
}
