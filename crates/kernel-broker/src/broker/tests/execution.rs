//! Tests for the unsandboxed and network-enabled execution bars.

use super::super::*;
use super::support::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Risk, Taint};

    #[tokio::test]
    async fn an_unsandboxed_call_forces_ask_over_an_allow_rule() {
        // The first call in a clean workspace, no taint involved: the mode
        // alone must raise the allow rule to an ask and mark the request.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &Taint::Clean,
                false,
                ExecutionMode::Unsandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "the denied ask must not run");
        assert!(
            auth.reason().contains("unsandboxed"),
            "reason: {}",
            auth.reason()
        );
        let calls = approver.calls();
        assert_eq!(calls.len(), 1, "the allow rule must not skip the ask");
        assert!(calls[0].unsandboxed, "the card must say it is unsandboxed");
        assert!(!calls[0].tainted);
    }

    #[tokio::test]
    async fn a_networked_call_forces_ask_over_an_allow_rule() {
        // SHELL-NETWORK-ASK: `[shell] network = true` leaves every socket
        // open. A stored allow rule must not auto-run the command: the first
        // call asks, the card names the network, and a deny means nothing runs.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &Taint::Clean,
                false,
                ExecutionMode::Networked,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "the denied ask must not run");
        assert!(
            auth.reason().contains("network"),
            "reason: {}",
            auth.reason()
        );
        let calls = approver.calls();
        assert_eq!(calls.len(), 1, "the allow rule must not skip the ask");
        assert!(calls[0].networked, "the card must say the network is on");
        assert!(!calls[0].unsandboxed, "the filesystem sandbox is still on");
        assert!(!calls[0].tainted);
        let payloads = sink.payloads("tool.decision");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["mode"], "networked", "{}", payloads[0]);
    }

    #[tokio::test]
    async fn an_unsandboxed_read_only_tool_is_not_exempted() {
        // The read-only declaration exempts a call from the taint raise only;
        // it says nothing about the sandbox escape hatch.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "read_only_shellish", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "read_only_shellish",
                Risk::Low,
                serde_json::Value::Null,
                &Taint::Clean,
                true,
                ExecutionMode::Unsandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "an unsandboxed read must still ask");
        assert_eq!(approver.calls().len(), 1);
    }

    #[tokio::test]
    async fn a_deny_rule_still_wins_for_an_unsandboxed_call() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Deny)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &Taint::Clean,
                false,
                ExecutionMode::Unsandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "deny still wins");
        assert!(approver.calls().is_empty(), "deny never asks");
    }

    #[tokio::test]
    async fn a_sandboxed_call_keeps_its_allow_rule() {
        // No over-asking: with the mode explicitly sandboxed, a clean
        // conversation and an allow rule run without an approver call (the
        // behaviour before the unsandboxed bar existed).
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed());
        assert!(
            approver.calls().is_empty(),
            "a sandboxed allow must not ask"
        );
        assert_eq!(sink.count("tool.decision"), 1);
    }
}
