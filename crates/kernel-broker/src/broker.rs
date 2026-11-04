//! The permission broker: ordered rules, an approval callback, and an audit
//! trail for every decision.
//!
//! Rules are evaluated in the order they are given and the **last match
//! wins** — put your default first and exceptions after it (the same idea as
//! firewalls and OpenCode policies). A [`Rule`] may scope an agent and/or a tool
//! with the [`ANY`] wildcard.
//! When no rule matches, the broker asks — except for a tool the caller
//! declares **read-only by construction** (H-02): a declared read-only tool
//! with no matching deny rule runs with a `tool.decision` audit row and no
//! approval card. Reads are the daily-use path; the effectful default stays
//! conservative.
//!
//! **Taint:** when the conversation holds untrusted content, the
//! broker raises the bar: every consequential call asks even if an `allow`
//! rule matches, and the [`ApprovalRequest`] tells the approver it is tainted
//! (so "always allow" can be refused). `deny` rules still win, tools the
//! caller declares **read-only by construction** keep their rule, and an
//! unknown taint state fails closed. [`Risk`] is informational: it is shown
//! and audited but never exempts a call, because a side-effecting tool that
//! under-reports its risk must not slip past the taint raise.
//!
//! Every decision — allow, deny, and both `ask` outcomes, including approver
//! failures — is written to the store as a `tool.decision` event whose payload
//! is JSON.
//!
//! **Execution mode:** a call that will run **unsandboxed** is
//! never auto-run by an `allow` rule. An `allow` rule is raised to `ask`
//! exactly as taint does (deny rules still win; a `read_only` declaration does
//! not exempt an unsandboxed call). The [`ApprovalRequest`] carries
//! `unsandboxed: true`, and the audit row records `mode = "unsandboxed"`.
//! The CLI's `--auto-approve` approver denies these asks; an interactive
//! approver may still explicitly approve them. This holds for the **first**
//! call in a clean workspace: it is a property of how the tool is built, not
//! of any prior taint mark. The caller passes [`ExecutionMode::Sandboxed`] as
//! the default; an unknown mode fails closed (unsandboxed).
//!
//! **Network-enabled shell (SHELL-NETWORK-ASK):** a sandboxed `shell` call
//! whose profile has `network = true` reports [`ExecutionMode::Networked`]. It
//! gets the same bar: no `allow` rule — and no persisted "always allow" — may
//! auto-run it, the [`ApprovalRequest`] carries `networked: true`, and the
//! audit row records `mode = "networked"`. A call that owns neither a sandbox
//! escape nor all sockets is still `Sandboxed` and keeps its allow-rule
//! behaviour.
//!
//! **Edited drafts:** an [`Approver`] may answer an ask with an
//! [`ApprovalDecision`] that substitutes the argument payload — the app's
//! `edit` decision. The broker then authorizes the *substituted* arguments:
//! they run under the same rule set, taint and execution mode as the ask
//! (a deny rule can never be edited around), they are held to the same
//! [`MAX_EDITED_ARGUMENTS_BYTES`] cap, and the `tool.decision` row carries
//! the SHA-256 of both the requested and the executed payload. Argument-
//! dependent gates that live in the caller (the web egress policy) must be
//! re-run on the substituted payload by that caller before it runs; the
//! broker never treats an approved edit as a fresh allowance of a different
//! resource.

mod admit;
mod approval;
mod audit;
mod digest;
mod policy;

pub use admit::{AuthorizeRequest, Broker, SkillOnlyLookup};
pub use approval::{ApprovalDecision, ApprovalRequest, Approver, ApproverError, Authorization};
#[cfg(any(test, feature = "test-util"))]
pub use audit::MemoryAuditSink;
pub use audit::{AuditError, AuditSink, BrokerError};
pub use policy::{
    matching_rule, Action, ExecutionMode, Rule, SkillRef, ANY, MAX_EDITED_ARGUMENTS_BYTES,
    SKILL_ONLY_REASON,
};

#[cfg(test)]
mod tests;
