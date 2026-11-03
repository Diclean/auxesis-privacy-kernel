//! Tests for rule matching, decisions, approvals and the audit trail.

use super::super::*;
use super::support::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TaintSource;
    use crate::{Risk, Taint};

    #[tokio::test]
    async fn ask_approver_receives_arguments() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let arguments = serde_json::json!({"command": "echo hi"});
        let auth = broker
            .authorize(request("main", "shell", Risk::High, arguments.clone()))
            .await
            .unwrap();
        assert!(auth.is_allowed());

        let calls = approver.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].arguments, arguments);

        // The wrapper without arguments attaches `null`, never stale data.
        let bare = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(sink.clone(), vec![], bare.clone(), no_skill_only());
        broker
            .authorize(request(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();
        assert_eq!(bare.calls()[0].arguments, serde_json::Value::Null);
    }

    #[tokio::test]
    async fn explicit_rule_tools_ignore_wildcard_allows_but_keep_exact_allows() {
        let sink = sink();
        let wildcard_approver = ScriptedApprover::new(Outcome::Approve);
        let wildcard = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, ANY, Action::Allow)],
            wildcard_approver.clone(),
            no_skill_only(),
        );
        let result = wildcard
            .authorize(request_with(
                "main",
                "google_gmail_create_draft",
                Risk::Medium,
                serde_json::json!({"to":"owner@example.test"}),
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                true,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(result.is_allowed());
        assert_eq!(
            wildcard_approver.calls().len(),
            1,
            "wildcard allow must ask"
        );

        let exact_approver = ScriptedApprover::new(Outcome::Approve);
        let exact = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, "google_gmail_create_draft", Action::Allow)],
            exact_approver.clone(),
            no_skill_only(),
        );
        let result = exact
            .authorize(request_with(
                "main",
                "google_gmail_create_draft",
                Risk::Medium,
                serde_json::json!({"to":"owner@example.test"}),
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                true,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(result.is_allowed());
        assert!(exact_approver.calls().is_empty(), "exact allow is retained");

        let ordinary_approver = ScriptedApprover::new(Outcome::Approve);
        let ordinary = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, ANY, Action::Allow)],
            ordinary_approver.clone(),
            no_skill_only(),
        );
        let result = ordinary
            .authorize(request_with(
                "main",
                "ordinary_tool",
                Risk::Medium,
                serde_json::json!({}),
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(result.is_allowed());
        assert!(ordinary_approver.calls().is_empty());
    }

    #[tokio::test]
    async fn explicit_rule_tools_always_ask_in_tainted_conversations() {
        let sink = sink();
        for rule in [
            Rule::new(ANY, ANY, Action::Allow),
            Rule::new(ANY, "google_gmail_create_draft", Action::Allow),
        ] {
            let approver = ScriptedApprover::new(Outcome::Approve);
            let broker = Broker::new(
                sink.clone(),
                vec![rule.clone()],
                approver.clone(),
                no_skill_only(),
            );
            let result = broker
                .authorize(request_with(
                    "main",
                    "google_gmail_create_draft",
                    Risk::Medium,
                    serde_json::json!({"to":"owner@example.test"}),
                    &Taint::Tainted(TaintSource::new("test", None)),
                    false,
                    ExecutionMode::Sandboxed,
                    true,
                    false,
                    None,
                ))
                .await
                .unwrap();
            assert!(result.is_allowed());
            assert_eq!(approver.calls().len(), 1, "taint must ask for {rule:?}");
        }
    }

    #[tokio::test]
    async fn allow_rule_allows_without_asking() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed());
        assert!(approver.calls().is_empty(), "allow must not ask");
        assert_eq!(sink.count("tool.decision"), 1);
    }

    #[tokio::test]
    async fn deny_rule_denies_without_asking() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Deny)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed());
        assert!(approver.calls().is_empty(), "deny must not ask");
        assert_eq!(sink.count("tool.decision"), 1);
    }

    #[tokio::test]
    async fn ask_rule_approved_allows() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "write_file", Action::Ask)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "write_file",
                Risk::Medium,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed());
        assert_eq!(
            approver.calls(),
            vec![ApprovalRequest {
                agent: "main".to_string(),
                tool: "write_file".to_string(),
                risk: Risk::Medium,
                arguments: serde_json::Value::Null,
                tainted: false,
                taint_source: None,
                web_approval: None,
                unsandboxed: false,
                networked: false,
            }]
        );
        assert_eq!(sink.count("tool.decision"), 1);
    }

    #[tokio::test]
    async fn ask_rule_denied_denies() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "write_file", Action::Ask)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "write_file",
                Risk::Medium,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed());
        assert_eq!(approver.calls().len(), 1);
        assert_eq!(sink.count("tool.decision"), 1);
    }

    #[tokio::test]
    async fn failing_approver_fails_closed() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Fail);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Ask)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "approver failure must deny");
        assert!(auth.reason().contains("fail closed"), "{}", auth.reason());
        assert_eq!(sink.count("tool.decision"), 1);
    }

    #[tokio::test]
    async fn last_match_wins_deny_after_allow() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", "shell", Action::Allow),
                Rule::new("main", "shell", Action::Deny),
            ],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "the later deny rule wins");
        assert!(approver.calls().is_empty());
    }

    #[tokio::test]
    async fn last_match_wins_allow_after_deny() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", "shell", Action::Deny),
                Rule::new("main", "shell", Action::Allow),
            ],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed(), "the later allow rule wins");
        assert!(approver.calls().is_empty());
    }

    #[tokio::test]
    async fn wildcard_rule_matches_any_tool_and_agent() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, ANY, Action::Deny)],
            approver.clone(),
            no_skill_only(),
        );

        let first = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();
        let second = broker
            .authorize(request(
                "work",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!first.is_allowed());
        assert!(!second.is_allowed());
        assert!(approver.calls().is_empty());
        assert_eq!(sink.count("tool.decision"), 2);
    }

    #[tokio::test]
    async fn rules_are_scoped_per_agent() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", "shell", Action::Allow),
                Rule::new("work", "shell", Action::Deny),
            ],
            approver.clone(),
            no_skill_only(),
        );

        assert!(broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null
            ))
            .await
            .unwrap()
            .is_allowed());
        assert!(!broker
            .authorize(request(
                "work",
                "shell",
                Risk::High,
                serde_json::Value::Null
            ))
            .await
            .unwrap()
            .is_allowed());
        assert_eq!(sink.count("tool.decision"), 2);
    }

    #[tokio::test]
    async fn no_matching_rule_asks_by_default() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed());
        assert_eq!(
            approver.calls(),
            vec![ApprovalRequest {
                agent: "main".to_string(),
                tool: "shell".to_string(),
                risk: Risk::High,
                arguments: serde_json::Value::Null,
                tainted: false,
                taint_source: None,
                web_approval: None,
                unsandboxed: false,
                networked: false,
            }]
        );
    }

    #[tokio::test]
    async fn no_matching_rule_can_be_approved() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed());
        assert_eq!(approver.calls().len(), 1);
    }

    #[tokio::test]
    async fn every_decision_is_audited_once() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", ANY, Action::Ask)],
            approver.clone(),
            no_skill_only(),
        );

        broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();
        broker
            .authorize(request(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();
        // An agent with no matching rule still goes through the default ask.
        broker
            .authorize(request(
                "work",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert_eq!(sink.count("tool.decision"), 3);
    }

    #[test]
    fn rule_matching_supports_wildcards() {
        let specific = Rule::new("main", "shell", Action::Allow);
        assert!(specific.matches("main", "shell"));
        assert!(!specific.matches("main", "read_file"));
        assert!(!specific.matches("work", "shell"));

        let any_tool = Rule::new("main", ANY, Action::Deny);
        assert!(any_tool.matches("main", "shell"));
        assert!(any_tool.matches("main", "read_file"));
        assert!(!any_tool.matches("work", "shell"));

        let any_agent = Rule::new(ANY, "shell", Action::Ask);
        assert!(any_agent.matches("main", "shell"));
        assert!(any_agent.matches("work", "shell"));
        assert!(!any_agent.matches("main", "read_file"));

        let catch_all = Rule::new(ANY, ANY, Action::Deny);
        assert!(catch_all.matches("main", "shell"));
        assert!(catch_all.matches("work", "read_file"));
    }

    #[test]
    fn action_labels_are_lowercase() {
        assert_eq!(Action::Allow.as_str(), "allow");
        assert_eq!(Action::Ask.to_string(), "ask");
        assert_eq!(
            serde_json::to_value(Action::Deny).unwrap(),
            serde_json::json!("deny")
        );
    }

    #[test]
    fn rules_accessor_keeps_order() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", ANY, Action::Allow),
                Rule::new(ANY, "shell", Action::Deny),
            ],
            approver,
            no_skill_only(),
        );

        assert_eq!(broker.rules().len(), 2);
        assert_eq!(broker.rules()[0].tool, ANY);
        assert_eq!(broker.rules()[1].action, Action::Deny);
    }
}
