//! Tests for the skill-only floor, including the live registry lookup.

use super::super::*;
use super::support::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Risk, Taint};
    use async_trait::async_trait;
    use std::sync::{Arc, RwLock};

    fn skill(name: &str) -> SkillRef {
        SkillRef {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            hash: "sha256:abc123".to_string(),
        }
    }

    /// The argument list every skill-floor test uses, so the two cases differ
    /// only by the skill context.
    #[allow(clippy::too_many_arguments)]
    async fn authorize_skill_only(
        broker: &Broker,
        skill_only: bool,
        skill: Option<&SkillRef>,
    ) -> Authorization {
        broker
            .authorize(request_with(
                "main",
                "google_gmail_send",
                Risk::High,
                serde_json::json!({"to": "owner@example.test"}),
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                true,
                skill_only,
                skill,
            ))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_skill_only_tool_without_a_skill_is_denied_before_the_approver() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        // Even the strongest rule cannot reach the approver: the hardline
        // floor runs before any rule match and before the approver is asked.
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, "google_gmail_send", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );
        match authorize_skill_only(&broker, true, None).await {
            Authorization::Denied { reason } => assert_eq!(reason, SKILL_ONLY_REASON),
            other => panic!("expected Denied, got {other:?}"),
        }
        assert!(
            approver.calls().is_empty(),
            "the approver must never be consulted for a skill-only denial"
        );
        let payloads = sink.payloads("tool.decision");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["action"], "deny");
        assert_eq!(payloads[0]["reason"], SKILL_ONLY_REASON);
    }

    #[tokio::test]
    async fn a_skill_only_tool_inside_a_skill_still_asks_under_an_allow_rule() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        // An exact allow rule is the strongest thing that can match a
        // skill-only tool (a wildcard never does): it must still ask.
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, "google_gmail_send", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );
        let context = skill("gmail_send");
        let auth = authorize_skill_only(&broker, true, Some(&context)).await;
        assert!(auth.is_allowed());
        assert_eq!(
            approver.calls().len(),
            1,
            "an allow rule cannot lift the skill floor: the call must ask"
        );
        assert!(
            auth.reason().contains("skill-only"),
            "the audit must name the floor: {}",
            auth.reason()
        );

        // A deny rule still wins over the skill floor.
        let denying = Broker::new(
            sink,
            vec![Rule::new(ANY, "google_gmail_send", Action::Deny)],
            ScriptedApprover::new(Outcome::Approve),
            no_skill_only(),
        );
        assert!(matches!(
            authorize_skill_only(&denying, true, Some(&context)).await,
            Authorization::Denied { .. }
        ));
    }

    #[tokio::test]
    async fn a_tool_that_is_not_skill_only_is_unaffected_by_the_context() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink,
            vec![Rule::new(ANY, "google_gmail_send", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );
        // Not skill-only, no context: the allow rule runs it without an ask.
        let auth = authorize_skill_only(&broker, false, None).await;
        assert!(auth.is_allowed());
        assert!(approver.calls().is_empty());
        // Not skill-only, with a context: the context never weakens anything.
        let context = skill("gmail_send");
        let auth = authorize_skill_only(&broker, false, Some(&context)).await;
        assert!(auth.is_allowed());
        assert!(approver.calls().is_empty());
    }

    /// A tool that declares the hardline skill floor in its own class.
    struct GmailSend;

    #[async_trait]
    impl crate::Tool for GmailSend {
        fn name(&self) -> &str {
            "gmail_send"
        }

        fn schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object"})
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &crate::ToolCtx,
        ) -> Result<crate::ToolOutput, crate::ToolError> {
            Ok(crate::ToolOutput::ok(""))
        }

        fn risk(&self) -> Risk {
            Risk::High
        }

        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B8
        }

        fn class(&self) -> crate::ToolClass {
            crate::ToolClass {
                skill_only: true,
                ..crate::ToolClass::default()
            }
        }
    }

    #[tokio::test]
    async fn a_tool_registered_after_the_broker_was_built_is_denied_without_a_skill() {
        // Seal probe_e: the floor is **live**, not a snapshot. The broker is
        // built first, holding a handle on the shared registry; `gmail_send`
        // is registered skill-only only afterwards. The request says
        // `skill_only: false` and an exact `allow` rule matches — the call must
        // still be denied with SKILL_ONLY_REASON, before the approver is
        // consulted.
        let registry = Arc::new(RwLock::new(crate::ToolRegistry::new()));
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, "gmail_send", Action::Allow)],
            approver.clone(),
            registry.clone(),
        );

        // Nothing is skill-only yet: the live lookup answers `false`.
        assert!(!SkillOnlyLookup::is_skill_only(
            &*registry.read().unwrap(),
            "gmail_send"
        ));

        // The registration happens after the broker exists.
        registry.write().unwrap().register(Box::new(GmailSend));
        assert_eq!(registry.read().unwrap().skill_only_tools(), ["gmail_send"]);

        let auth = broker
            .authorize(request(
                "main",
                "gmail_send",
                Risk::High,
                serde_json::json!({"to": "owner@example.test"}),
            ))
            .await
            .unwrap();
        match auth {
            Authorization::Denied { reason } => assert_eq!(reason, SKILL_ONLY_REASON),
            other => panic!("expected Denied, got {other:?}"),
        }
        assert!(
            approver.calls().is_empty(),
            "the approver must never be consulted for a skill-only denial"
        );
        let payloads = sink.payloads("tool.decision");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["action"], "deny");
        assert_eq!(payloads[0]["reason"], SKILL_ONLY_REASON);
    }
}
