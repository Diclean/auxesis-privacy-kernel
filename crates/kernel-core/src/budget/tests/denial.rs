//! Tests for denial text and audit payloads.

use super::super::*;
use super::support::FakeAudit;

#[test]
fn reservation_denials_explain_reserved_spend() {
    let denial = Denial {
        agent: "main".to_string(),
        day: "2026-10-03".to_string(),
        reason: DenialReason::CapExceeded {
            kind: UsageKind::TokensIn,
            spent: 40,
            reserved: 60,
            limit: 100,
        },
        audit_error: None,
    };

    let text = denial.reason_text();
    assert!(text.contains("40 spent + 60 reserved / 100"), "{text}");
    let payload = denial.audit_payload();
    assert!(payload.contains(r#""spent":40"#), "{payload}");
    assert!(payload.contains(r#""reserved":60"#), "{payload}");
    assert!(payload.contains(r#""limit":100"#), "{payload}");
}

#[test]
fn fail_closed_denials_explain_the_latch() {
    let denial = Denial {
        agent: "main".to_string(),
        day: "2026-10-03".to_string(),
        reason: DenialReason::FailClosed {
            message: "a completed call reached the daily tokens_out budget (90/50)".to_string(),
        },
        audit_error: None,
    };

    let text = denial.reason_text();
    assert!(text.contains("failing closed"), "{text}");
    assert!(text.contains("tokens_out budget (90/50)"), "{text}");
    assert!(text.contains("2026-10-03"), "{text}");
    let payload = denial.audit_payload();
    assert!(payload.contains(r#""fail_closed":true"#), "{payload}");
    assert!(payload.contains("tokens_out budget"), "{payload}");
}

#[test]
fn audit_denial_records_a_failing_sink_on_the_denial() {
    let denial = Denial {
        agent: "main".to_string(),
        day: "2026-10-03".to_string(),
        reason: DenialReason::CapExceeded {
            kind: UsageKind::TokensOut,
            spent: 1,
            reserved: 0,
            limit: 1,
        },
        audit_error: None,
    };
    let audit = FakeAudit {
        fail: true,
        ..FakeAudit::default()
    };

    let denial = audit_denial(&audit, denial);
    assert_eq!(
        denial.audit_error.as_deref(),
        Some("audit sink unavailable: disk full")
    );
    assert!(denial.audit_payload().contains("audit failed"));
}
