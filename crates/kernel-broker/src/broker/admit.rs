//! The broker itself: rule evaluation, the approval path and the audit row.

use super::approval::{ApprovalRequest, Approver, Authorization};
use super::audit::{AuditSink, BrokerError};
use super::digest::arguments_sha256;
use super::policy::{
    matching_rule, Action, ExecutionMode, Rule, SkillRef, MAX_EDITED_ARGUMENTS_BYTES,
    SKILL_ONLY_REASON,
};
use crate::{Risk, Taint};
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Serialize)]
struct AuditRecord {
    agent: String,
    tool: String,
    risk: Risk,
    action: &'static str,
    outcome: &'static str,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Conversation taint state at decision time.
    tainted: bool,
    /// What introduced the untrusted content, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    taint_source: Option<String>,
    /// How the call will execute (`sandboxed` / `unsandboxed` / `networked`).
    mode: &'static str,
    /// SHA-256 (hex) of the arguments the caller requested, present only when
    /// an approver substituted an edited draft.
    #[serde(skip_serializing_if = "Option::is_none")]
    original_args_sha256: Option<String>,
    /// SHA-256 (hex) of the arguments that were authorized to run (the edited
    /// draft), present only when an approver substituted one.
    #[serde(skip_serializing_if = "Option::is_none")]
    executed_args_sha256: Option<String>,
}

/// The inputs of one authorization call, all required.
///
/// Every bar the broker applies is named here: there is no `Default` and no
/// shorthand constructor, so a caller cannot omit taint, read-only, execution
/// mode, explicit-rule, skill context or the skill-only declaration by
/// accident. `skill_only: false` never lowers a tool the broker's live
/// [`SkillOnlyLookup`] reports as skill-only: the broker raises the floor by
/// name regardless of this field.
#[derive(Debug, Clone)]
pub struct AuthorizeRequest<'a> {
    /// Agent that wants to run the tool.
    pub agent: &'a str,
    /// Name of the tool.
    pub tool: &'a str,
    /// Risk classification of the tool.
    pub risk: Risk,
    /// Arguments the tool would run with. Shown to the approver; never written
    /// to the audit record.
    pub arguments: serde_json::Value,
    /// Taint state of the conversation. An unknown state behaves as tainted.
    pub taint: &'a Taint,
    /// True when the caller declares the tool read-only by construction: it
    /// observes local state and produces no side effects.
    pub read_only: bool,
    /// How the call will execute ([`ExecutionMode::forces_ask`] refuses every
    /// persistent allow).
    pub mode: ExecutionMode,
    /// True when a wildcard `allow` rule must not authorize this tool.
    pub requires_explicit_rule: bool,
    /// The skill context of the call, when it runs inside a skill.
    pub skill: Option<&'a SkillRef>,
    /// True when the tool declares [`crate::ToolClassExt::skill_only`].
    pub skill_only: bool,
}

/// The live answer to "is this tool skill-only?".
///
/// The broker's hardline skill floor is a property of the **tool**, not of a
/// caller's bookkeeping, so the broker asks this on every
/// [`Broker::authorize`] call instead of copying a name set at build time.
/// [`crate::ToolRegistry`] implements it by reading the class of the tool
/// registered under that name *right now*; hold the registry behind an
/// `Arc<RwLock<_>>` so a tool registered after the broker was built is still
/// covered.
pub trait SkillOnlyLookup: Send + Sync {
    /// True when `tool` declares [`crate::ToolClassExt::skill_only`] right now.
    fn is_skill_only(&self, tool: &str) -> bool;
}

/// Decides whether an agent may run a tool, with an audit record for each call.
pub struct Broker {
    rules: Vec<Rule>,
    sink: Arc<dyn AuditSink>,
    approver: Arc<dyn Approver>,
    /// The live skill floor, consulted on every [`Self::authorize`] call. A
    /// mandatory constructor argument: no `Default`, no `Option`, no builder
    /// that skips it, and no method that replaces or clears it.
    skill_only: Arc<dyn SkillOnlyLookup>,
}

impl Broker {
    /// Build a broker for `rules`, auditing to `sink`, asking `approver` when
    /// needed, and taking the skill floor from `skill_only`.
    ///
    /// All four arguments are mandatory. A broker cannot be built without an
    /// answer to "is this tool skill-only?", and the round-1 optional
    /// `with_skill_only_tools` is gone: there is no method to replace or clear
    /// the lookup after the fact. The seal's probe does not compile — three
    /// arguments are not enough:
    ///
    /// ```compile_fail,E0061
    /// fn _probe(
    ///     sink: std::sync::Arc<dyn kernel_broker::AuditSink>,
    ///     rules: Vec<kernel_broker::Rule>,
    ///     approver: std::sync::Arc<dyn kernel_broker::Approver>,
    /// ) {
    ///     let _ = kernel_broker::Broker::new(sink, rules, approver);
    /// }
    /// ```
    ///
    /// and neither is a setter. The probe takes the broker **by value**, so
    /// before this fix it compiled (the method existed) and now it fails with
    /// `E0599`:
    ///
    /// ```compile_fail,E0599
    /// fn _probe(broker: kernel_broker::Broker) {
    ///     let _ = broker.with_skill_only_tools(["gmail_send"]);
    /// }
    /// ```
    pub fn new(
        sink: Arc<dyn AuditSink>,
        rules: Vec<Rule>,
        approver: Arc<dyn Approver>,
        skill_only: Arc<dyn SkillOnlyLookup>,
    ) -> Self {
        Self {
            rules,
            sink,
            approver,
            skill_only,
        }
    }

    /// The configured rules, in evaluation order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The one authorization entry point.
    ///
    /// Evaluation is ordered: the last matching rule wins (defaults first,
    /// exceptions after). With no match the broker asks, and a missing
    /// approver answer (error) is a denial. A tainted conversation raises
    /// every consequential `allow` to `ask`; an unsandboxed call is raised
    /// regardless of taint; and a skill-only tool (by the request's
    /// declaration or the live [`SkillOnlyLookup`]) is **denied** with
    /// [`SKILL_ONLY_REASON`] when `skill` is `None`, or held to at least `ask`
    /// when it is `Some` — all before the approver is consulted for the
    /// denial. `deny` rules still win everywhere.
    pub async fn authorize(&self, req: AuthorizeRequest<'_>) -> Result<Authorization, BrokerError> {
        // The hardline floor is a property of the tool, not of the caller's
        // bookkeeping: a name the live lookup reports as skill-only is
        // skill-only whatever the request says. The lookup is consulted here,
        // at authorization time, so a tool registered after this broker was
        // built is covered.
        let skill_only = req.skill_only || self.skill_only.is_skill_only(req.tool);
        self.authorize_inner(req, skill_only).await
    }

    /// The authorization body, with the skill floor already resolved.
    async fn authorize_inner(
        &self,
        req: AuthorizeRequest<'_>,
        skill_only: bool,
    ) -> Result<Authorization, BrokerError> {
        let AuthorizeRequest {
            agent,
            tool,
            risk,
            arguments,
            taint,
            read_only,
            mode,
            requires_explicit_rule,
            skill,
            skill_only: _,
        } = req;
        let tainted = taint.forces_ask();
        let taint_source = taint.summary();
        let unsandboxed = mode.is_unsandboxed();
        let networked = mode.is_networked();

        // Hardline floor (soul rule 1): a skill-only tool
        // requested without a skill context is refused here, before any rule
        // match and before the approver is asked anything.
        if skill_only && skill.is_none() {
            let reason = SKILL_ONLY_REASON.to_string();
            self.audit(AuditRecord {
                agent: agent.to_string(),
                tool: tool.to_string(),
                risk,
                action: Action::Deny.as_str(),
                outcome: "denied",
                reason: reason.clone(),
                rule: None,
                approved: None,
                error: None,
                tainted,
                taint_source,
                mode: mode.as_str(),
                original_args_sha256: None,
                executed_args_sha256: None,
            })?;
            return Ok(Authorization::Denied { reason });
        }

        // Last matching rule wins: defaults first, exceptions after.
        let matched = matching_rule(&self.rules, agent, tool, requires_explicit_rule);
        // H-02 (calibration): the no-rule default for a tool the caller
        // declares read-only is **allow** — an audit row, no approval card.
        // Reads are the daily-use path and a read-only tool cannot move data
        // or run anything. The two existing bars stay exactly as before:
        // taint still asks, and an unsandboxed or network-enabled call still
        // asks (a matching rule still wins in both directions).
        let read_only_default = matched.is_none() && read_only && !tainted && !mode.forces_ask();
        let (rule_index, rule_action) = match matched {
            Some((index, rule)) => (Some(index), rule.action),
            None if read_only_default => (None, Action::Allow),
            None => (None, Action::Ask),
        };
        // Three independent bars can raise an `allow` rule to `ask`:
        // - taint: untrusted content is in the conversation, so a
        //   consequential call must be approved (an explicit read-only
        //   declaration is the only exemption);
        // - unsandboxed: the call will escape its sandbox, so no `allow`
        //   rule — and no persisted "always allow" — may auto-run it, ever;
        // - networked: the sandbox has every socket open, so the same bar
        //   applies even though the filesystem is still confined.
        // `Risk` is deliberately not consulted for either: a tool that
        // under-reports its risk must still ask.
        //
        // The skill floor is the fourth: a skill-only tool running inside a
        // skill asks at minimum, so an `allow` rule cannot lift it either.
        let skill_floor = skill_only && skill.is_some();
        let forced_reason = if skill_floor {
            Some(format!(
                "`{tool}` is skill-only and may run only inside a skill"
            ))
        } else if unsandboxed {
            Some(if tainted {
                format!(
                    "`{tool}` runs unsandboxed and the conversation is tainted ({})",
                    taint_source.as_deref().unwrap_or("unknown")
                )
            } else {
                format!("`{tool}` runs unsandboxed")
            })
        } else if networked {
            Some(if tainted {
                format!(
                    "`{tool}` runs with the network enabled and the conversation is tainted ({})",
                    taint_source.as_deref().unwrap_or("unknown")
                )
            } else {
                format!("`{tool}` runs with the network enabled (all sockets open)")
            })
        } else if tainted && !read_only {
            Some(format!(
                "the conversation is tainted ({}) and `{tool}` is consequential",
                taint_source.as_deref().unwrap_or("unknown")
            ))
        } else {
            None
        };
        let forced = rule_action == Action::Allow && forced_reason.is_some();
        let action = if forced { Action::Ask } else { rule_action };
        let label = match (rule_index, forced) {
            (Some(index), true) => format!(
                "rule {index} matched, but {}",
                forced_reason
                    .as_deref()
                    .unwrap_or("the call must be approved")
            ),
            (Some(index), false) => format!("rule {index} matched"),
            (None, true) => format!(
                "no matching rule, but {}",
                forced_reason
                    .as_deref()
                    .unwrap_or("the call must be approved")
            ),
            (None, _) if read_only_default => {
                "no matching rule (read-only tool, default allow)".to_string()
            }
            (None, _) => "no matching rule (default ask)".to_string(),
        };

        match action {
            Action::Allow | Action::Deny => {
                let outcome = if action == Action::Allow {
                    "allowed"
                } else {
                    "denied"
                };
                let reason = format!("{label}: {action}");
                self.audit(AuditRecord {
                    agent: agent.to_string(),
                    tool: tool.to_string(),
                    risk,
                    action: action.as_str(),
                    outcome,
                    reason: reason.clone(),
                    rule: rule_index,
                    approved: None,
                    error: None,
                    tainted,
                    taint_source,
                    mode: mode.as_str(),
                    original_args_sha256: None,
                    executed_args_sha256: None,
                })?;
                Ok(if action == Action::Allow {
                    Authorization::Allowed {
                        reason,
                        arguments,
                        edited: false,
                    }
                } else {
                    Authorization::Denied { reason }
                })
            }
            Action::Ask => {
                let requested = arguments;
                let request = ApprovalRequest {
                    agent: agent.to_string(),
                    tool: tool.to_string(),
                    risk,
                    arguments: requested.clone(),
                    tainted,
                    taint_source: taint_source.clone(),
                    web_approval: taint.source().and_then(|source| source.web_approval),
                    unsandboxed,
                    networked,
                };
                match self.approver.decide(&request).await {
                    Ok(decision) if decision.allow => {
                        // An edited draft is what runs; a plain approve keeps
                        // the request. The rule set, taint and mode are the
                        // same ones the ask was decided under, so an edit can
                        // never widen them. The 4 KiB preview cap is re-applied
                        // to the substituted payload as a hard floor.
                        let (executed, edited, original_args_sha256, executed_args_sha256) =
                            match decision.arguments {
                                Some(edited) => {
                                    let too_large = serde_json::to_vec(&edited)
                                        .map(|encoded| encoded.len() > MAX_EDITED_ARGUMENTS_BYTES)
                                        .unwrap_or(true);
                                    if too_large {
                                        let reason = format!(
                                            "{label}: ask, approved, but the edited draft exceeds the {MAX_EDITED_ARGUMENTS_BYTES} byte cap, denied"
                                        );
                                        self.audit(AuditRecord {
                                            agent: agent.to_string(),
                                            tool: tool.to_string(),
                                            risk,
                                            action: Action::Ask.as_str(),
                                            outcome: "denied",
                                            reason: reason.clone(),
                                            rule: rule_index,
                                            approved: Some(true),
                                            error: Some("edited_arguments_too_large".to_string()),
                                            tainted,
                                            taint_source,
                                            mode: mode.as_str(),
                                            original_args_sha256: Some(arguments_sha256(
                                                &requested,
                                            )),
                                            executed_args_sha256: Some(arguments_sha256(&edited)),
                                        })?;
                                        return Ok(Authorization::Denied { reason });
                                    }
                                    (
                                        edited.clone(),
                                        true,
                                        Some(arguments_sha256(&requested)),
                                        Some(arguments_sha256(&edited)),
                                    )
                                }
                                None => (requested, false, None, None),
                            };
                        let reason = format!("{label}: ask, approved");
                        self.audit(AuditRecord {
                            agent: agent.to_string(),
                            tool: tool.to_string(),
                            risk,
                            action: Action::Ask.as_str(),
                            outcome: "allowed",
                            reason: reason.clone(),
                            rule: rule_index,
                            approved: Some(true),
                            error: None,
                            tainted,
                            taint_source,
                            mode: mode.as_str(),
                            original_args_sha256,
                            executed_args_sha256,
                        })?;
                        Ok(Authorization::Allowed {
                            reason,
                            arguments: executed,
                            edited,
                        })
                    }
                    Ok(_) => {
                        let reason = format!("{label}: ask, denied");
                        self.audit(AuditRecord {
                            agent: agent.to_string(),
                            tool: tool.to_string(),
                            risk,
                            action: Action::Ask.as_str(),
                            outcome: "denied",
                            reason: reason.clone(),
                            rule: rule_index,
                            approved: Some(false),
                            error: None,
                            tainted,
                            taint_source,
                            mode: mode.as_str(),
                            original_args_sha256: None,
                            executed_args_sha256: None,
                        })?;
                        Ok(Authorization::Denied { reason })
                    }
                    Err(err) => {
                        // Fail closed: a broken approval channel is a denial.
                        let reason =
                            format!("{label}: ask, approver failed, denied (fail closed): {err}");
                        self.audit(AuditRecord {
                            agent: agent.to_string(),
                            tool: tool.to_string(),
                            risk,
                            action: Action::Ask.as_str(),
                            outcome: "denied",
                            reason: reason.clone(),
                            rule: rule_index,
                            approved: Some(false),
                            error: Some(err.to_string()),
                            tainted,
                            taint_source,
                            mode: mode.as_str(),
                            original_args_sha256: None,
                            executed_args_sha256: None,
                        })?;
                        Ok(Authorization::Denied { reason })
                    }
                }
            }
        }
    }

    fn audit(&self, record: AuditRecord) -> Result<(), BrokerError> {
        let payload = serde_json::to_value(&record)?;
        self.sink.log_event("tool.decision", &payload)?;
        Ok(())
    }
}
