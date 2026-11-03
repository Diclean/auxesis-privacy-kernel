//! Shared fixtures for the broker tests.

use super::super::*;
use crate::TaintSource;
use crate::{Risk, Taint};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

/// The lookup the tests that do not exercise the floor pass: no tool is
/// skill-only, so only the request's own `skill_only` declaration counts.
pub(super) struct NoSkillOnlyTools;

impl SkillOnlyLookup for NoSkillOnlyTools {
    fn is_skill_only(&self, _tool: &str) -> bool {
        false
    }
}

/// The mandatory [`Broker::new`] argument for those tests.
pub(super) fn no_skill_only() -> Arc<dyn SkillOnlyLookup> {
    Arc::new(NoSkillOnlyTools)
}

#[derive(Clone, Copy)]
pub(super) enum Outcome {
    Approve,
    Deny,
    Fail,
}

pub(super) struct ScriptedApprover {
    calls: Mutex<Vec<ApprovalRequest>>,
    outcome: Outcome,
}

impl ScriptedApprover {
    pub(super) fn new(outcome: Outcome) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            outcome,
        })
    }

    pub(super) fn calls(&self) -> Vec<ApprovalRequest> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl Approver for ScriptedApprover {
    async fn approve(&self, request: &ApprovalRequest) -> Result<bool, ApproverError> {
        self.calls.lock().unwrap().push(request.clone());
        match self.outcome {
            Outcome::Approve => Ok(true),
            Outcome::Deny => Ok(false),
            Outcome::Fail => Err(ApproverError("no approval UI attached".to_string())),
        }
    }
}

pub(super) fn sink() -> Arc<MemoryAuditSink> {
    Arc::new(MemoryAuditSink::new())
}

/// A clean taint state with a `'static` lifetime, so the request helpers
/// below can borrow it.
pub(super) static CLEAN: Taint = Taint::Clean;

/// A clean, sandboxed request with no explicit-rule or skill context.
pub(super) fn request<'a>(
    agent: &'a str,
    tool: &'a str,
    risk: Risk,
    arguments: serde_json::Value,
) -> AuthorizeRequest<'a> {
    request_with(
        agent,
        tool,
        risk,
        arguments,
        &CLEAN,
        false,
        ExecutionMode::Sandboxed,
        false,
        false,
        None,
    )
}

/// The full request, in the order the old entry points took their
/// arguments, so a test names every bar the broker applies.
#[allow(clippy::too_many_arguments)]
pub(super) fn request_with<'a>(
    agent: &'a str,
    tool: &'a str,
    risk: Risk,
    arguments: serde_json::Value,
    taint: &'a Taint,
    read_only: bool,
    mode: ExecutionMode,
    requires_explicit_rule: bool,
    skill_only: bool,
    skill: Option<&'a SkillRef>,
) -> AuthorizeRequest<'a> {
    AuthorizeRequest {
        agent,
        tool,
        risk,
        arguments,
        taint,
        read_only,
        mode,
        requires_explicit_rule,
        skill,
        skill_only,
    }
}

pub(super) fn tainted() -> Taint {
    Taint::Tainted(TaintSource::new(
        "http_fetch",
        Some("https://evil.example/page".to_string()),
    ))
}
