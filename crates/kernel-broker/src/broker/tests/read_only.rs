//! Tests for the declared read-only default and its limits.

use super::super::*;
use super::support::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Risk, Taint};

    #[tokio::test]
    async fn a_read_only_tool_with_no_rule_is_allowed_and_audited() {
        // H-02 (calibration): the no-rule default for a declared read-only
        // tool is allow — audit-logged, no approval card. The old default
        // (every unmatched call asks) made every read a prompt.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request_with(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
                &Taint::Clean,
                true,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed(), "a read-only default must not ask");
        assert!(
            auth.reason().contains("read-only tool, default allow"),
            "reason: {}",
            auth.reason()
        );
        assert!(
            approver.calls().is_empty(),
            "a read-only default must not raise a card"
        );
        assert_eq!(
            sink.count("tool.decision"),
            1,
            "the allowance is audit-logged"
        );
    }

    #[tokio::test]
    async fn a_read_only_default_never_beats_a_deny_or_explicit_ask_rule() {
        // H-02: the default only fills the **no match** case. A deny rule
        // still wins (non-negotiable #4), and an explicit `ask` rule on a
        // read-only tool still asks.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "read_file", Action::Deny)],
            approver.clone(),
            no_skill_only(),
        );
        let auth = broker
            .authorize(request_with(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
                &Taint::Clean,
                true,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(!auth.is_allowed(), "deny still wins over the read default");
        assert!(approver.calls().is_empty(), "deny never asks");

        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "read_file", Action::Ask)],
            approver.clone(),
            no_skill_only(),
        );
        let auth = broker
            .authorize(request_with(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
                &Taint::Clean,
                true,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(auth.is_allowed());
        assert_eq!(approver.calls().len(), 1, "an explicit ask still asks");
    }

    #[tokio::test]
    async fn a_non_read_only_tool_with_no_rule_still_asks_and_a_tainted_read_still_asks() {
        // H-02: everything that is not a declared read-only tool behaves
        // exactly as before. And a tainted conversation forces the read-only
        // tool to ask too (taint is never weakened by the new default).
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request_with(
                "main",
                "write_file",
                Risk::Medium,
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
        assert!(!auth.is_allowed(), "a consequential default still asks");
        assert_eq!(approver.calls().len(), 1);

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
        assert!(!auth.is_allowed(), "a tainted read still asks");
        let calls = approver.calls();
        assert_eq!(calls.len(), 2, "the tainted read raised a card");
        assert!(calls[1].tainted);
        assert!(
            calls[1]
                .taint_source
                .as_deref()
                .unwrap()
                .contains("http_fetch"),
            "the card names the source: {:?}",
            calls[1].taint_source
        );
    }

    #[tokio::test]
    async fn a_read_only_default_is_not_an_exemption_for_an_unsandboxed_call() {
        // H-02: the unsandboxed bar is independent and still wins: a
        // read-only call that will escape its sandbox is raised to ask.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

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
        let calls = approver.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].unsandboxed);
    }

    #[tokio::test]
    async fn a_tainted_turn_forces_ask_for_a_declared_read_only_tool_with_no_rule() {
        // H-02 invariant: the read-only no-rule default is strictly for clean
        // turns. Taint is a one-way ratchet: once untrusted content is in the
        // conversation, a declared read-only tool with no matching rule still
        // raises a card (the default requires `!tainted`). The engine must not
        // seed an allow rule for read-only tools, or this guard is dead.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

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

        assert!(!auth.is_allowed(), "a tainted read must ask");
        let calls = approver.calls();
        assert_eq!(calls.len(), 1, "the tainted read raised a card");
        assert!(calls[0].tainted);
        assert!(
            calls[0]
                .taint_source
                .as_deref()
                .unwrap()
                .contains("http_fetch"),
            "the card names the taint source"
        );
    }

    #[tokio::test]
    async fn http_fetch_is_never_auto_allowed() {
        // WEB-01: `http_fetch` is egress, not a local read, so the registry
        // never declares it read-only and the H-02 read default cannot fire
        // for it. With no rule it asks like any other effectful tool, clean
        // or tainted; it is never silently auto-run.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request_with(
                "main",
                "http_fetch",
                Risk::Medium,
                serde_json::Value::Null,
                &Taint::Clean, // The registry does not mark `http_fetch` read-only (tested in
                // `registry::tests::only_explicitly_declared_read_only_tools_are_exempt`).
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(
            !auth.is_allowed(),
            "an unknown fetch must ask, never auto-run"
        );
        assert_eq!(approver.calls().len(), 1);
    }
}
