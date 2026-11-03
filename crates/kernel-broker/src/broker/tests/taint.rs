//! Tests for the taint raise and its limits.

use super::super::*;
use super::support::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Risk, Taint};

    #[tokio::test]
    async fn tainted_conversation_forces_ask_over_an_allow_rule() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", "shell", Action::Allow),
                Rule::new("main", "read_file", Action::Allow),
            ],
            approver.clone(),
            no_skill_only(),
        );

        // The allow rule is ignored: the human is asked.
        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &tainted(),
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed(), "an approved call may still run");
        assert!(
            auth.reason().contains("tainted"),
            "reason: {}",
            auth.reason()
        );
        let calls = approver.calls();
        assert_eq!(calls.len(), 1, "the allow rule must not skip the ask");
        assert!(calls[0].tainted);
        assert_eq!(
            calls[0].taint_source.as_deref(),
            Some("http_fetch: https://evil.example/page")
        );
        assert_eq!(sink.count("tool.decision"), 1);

        // A declared read-only tool keeps its configured rule: no ask for a
        // low-risk allow even while tainted.
        let auth = broker
            .authorize(request_with(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
                &tainted(),
                true,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(auth.is_allowed());
        assert_eq!(approver.calls().len(), 1, "reads stay as configured");
    }

    #[tokio::test]
    async fn a_low_risk_side_effect_tool_is_not_exempt_from_the_taint_raise() {
        // `Risk` is informational: a side-effecting tool that self-reports
        // `low` must still ask while tainted. Only the explicit read-only
        // marker exempts a call.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "side_effect_writer", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "side_effect_writer",
                Risk::Low,
                serde_json::Value::Null,
                &tainted(),
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed(), "an approved call may still run");
        let calls = approver.calls();
        assert_eq!(calls.len(), 1, "a low-risk side effect must not slip past");
        assert!(calls[0].tainted);
    }

    #[tokio::test]
    async fn a_deny_rule_still_wins_and_unknown_state_fails_closed() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", "shell", Action::Deny),
                Rule::new("main", "write_file", Action::Allow),
            ],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &tainted(),
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(!auth.is_allowed(), "deny still wins");
        assert!(approver.calls().is_empty(), "deny never asks");

        // Unknown provenance acts like taint: the allow is raised to ask.
        let auth = broker
            .authorize(request_with(
                "main",
                "write_file",
                Risk::Medium,
                serde_json::Value::Null,
                &Taint::Unknown,
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(auth.is_allowed());
        let calls = approver.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].tainted);
        assert!(calls[0]
            .taint_source
            .as_deref()
            .unwrap()
            .contains("fail closed"));
    }
}
