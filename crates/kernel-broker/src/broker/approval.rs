//! Approval requests and decisions: what the broker asks, and what comes back.

use crate::Risk;
use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

/// A tool call waiting for a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalRequest {
    /// Agent that wants to run the tool.
    pub agent: String,
    /// Name of the tool.
    pub tool: String,
    /// Risk classification of the tool.
    pub risk: Risk,
    /// Arguments the tool would run with. Shown to the approver; deliberately
    /// never written to the audit log.
    pub arguments: serde_json::Value,
    /// True when the conversation is tainted (or its taint state is unknown,
    /// which fails closed): "always allow" must not be offered or accepted.
    pub tainted: bool,
    /// Summary of what introduced the untrusted content, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint_source: Option<String>,
    /// True when the call will run unsandboxed (the `[shell]` escape hatch):
    /// the card must say so and "always allow" must not be offered or
    /// accepted, exactly as for a tainted ask.
    pub unsandboxed: bool,
    /// True when the shell runs sandboxed with every socket open
    /// (`[shell] network = true`): the card must say so and "always allow"
    /// must not be offered or accepted, exactly as for an unsandboxed ask.
    pub networked: bool,
}

/// What an [`Approver`] decided for one ask.
///
/// A plain approve/deny is [`ApprovalDecision::new`] with no substitution.
/// An `edit` answer carries the substituted payload: the broker authorizes
/// **these** arguments instead of the requested ones, so the caller must run
/// them (and re-run any argument-dependent gate of its own).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecision {
    /// True when the ask may run.
    pub allow: bool,
    /// Arguments the approver substituted for the ask, or `None` to run the
    /// requested ones unchanged.
    pub arguments: Option<serde_json::Value>,
}

impl ApprovalDecision {
    /// An approve/deny with no argument substitution.
    pub fn new(allow: bool) -> Self {
        Self {
            allow,
            arguments: None,
        }
    }

    /// Approve the ask with `arguments` substituted for the requested ones
    /// (the app's `edit` decision).
    pub fn edited(arguments: serde_json::Value) -> Self {
        Self {
            allow: true,
            arguments: Some(arguments),
        }
    }
}

/// Callback consulted when a rule (or the default) says `ask`.
///
/// Implementations can prompt a human, consult another policy engine, or
/// auto-approve in tests. Returning an error is treated as a denial.
///
/// The broker calls [`Self::decide`]; the default defers to [`Self::approve`]
/// with no substitution, so an approver that never edits only implements
/// `approve`.
#[async_trait]
pub trait Approver: Send + Sync {
    /// Return `Ok(true)` to approve and `Ok(false)` to deny.
    async fn approve(&self, request: &ApprovalRequest) -> Result<bool, ApproverError>;

    /// Decide an ask, optionally substituting an edited draft.
    ///
    /// Defaults to [`Self::approve`] with no substitution. An interactive
    /// approver that supports the `edit` decision overrides this and returns
    /// [`ApprovalDecision::edited`].
    async fn decide(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApproverError> {
        Ok(ApprovalDecision::new(self.approve(request).await?))
    }
}

/// Error returned by an [`Approver`]; the broker fails closed and denies.
#[derive(Debug, Error)]
#[error("approver failed: {0}")]
pub struct ApproverError(pub String);

/// Outcome of a broker decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorization {
    /// The call may run.
    Allowed {
        /// Human-readable justification (matched rule or approval).
        reason: String,
        /// The arguments authorized to run: the requested ones, or the
        /// approver's edited draft when it substituted them.
        arguments: serde_json::Value,
        /// True when the approver explicitly substituted an edited draft,
        /// including when its value happens to equal the requested payload.
        edited: bool,
    },
    /// The call must not run.
    Denied {
        /// Human-readable justification.
        reason: String,
    },
}

impl Authorization {
    /// True for [`Authorization::Allowed`].
    pub fn is_allowed(&self) -> bool {
        matches!(self, Authorization::Allowed { .. })
    }

    /// Human-readable justification for the decision.
    pub fn reason(&self) -> &str {
        match self {
            Authorization::Allowed { reason, .. } | Authorization::Denied { reason } => reason,
        }
    }

    /// The arguments authorized to run, when the call is allowed.
    ///
    /// For an allowed call this is always present: the edited draft when the
    /// approver substituted one, else the requested arguments.
    pub fn arguments(&self) -> Option<&serde_json::Value> {
        match self {
            Authorization::Allowed { arguments, .. } => Some(arguments),
            Authorization::Denied { .. } => None,
        }
    }

    /// Whether an allowed call was authorized with an approver-substituted
    /// draft.
    pub fn arguments_were_edited(&self) -> bool {
        matches!(self, Authorization::Allowed { edited: true, .. })
    }
}
