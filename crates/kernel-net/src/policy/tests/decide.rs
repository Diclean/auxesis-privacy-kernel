//! Tests for the mode/private-data decision and the sensitive-turn rule.

use kernel_core::{WebConfig, WebMode};

use super::super::host::url_origin_key;
use super::super::*;
use super::support::web_gate;

#[test]
fn deny_wins_over_allow_in_every_mode() {
    for mode in [
        WebMode::OpenRead,
        WebMode::Smart,
        WebMode::AskOncePerSite,
        WebMode::AlwaysAsk,
    ] {
        let gate = web_gate(WebConfig {
            mode,
            allow_domains: vec!["*.example.com".to_string()],
            deny_domains: vec!["ads.example.com".to_string()],
            ..WebConfig::default()
        });
        let ctx = EgressContext {
            seen_origin: true,
            ..EgressContext::default()
        };
        assert_eq!(
            gate.decide("https://ads.example.com/pixel", &ctx),
            EgressDecision::Deny(DenyReason::DeniedDomain),
            "{mode}"
        );
        // A non-denied sibling is still allowlisted without a card.
        assert_eq!(
            gate.decide("https://docs.example.com/page", &ctx),
            EgressDecision::Allow,
            "{mode}"
        );
    }
}

fn sensitive_seen() -> EgressContext {
    EgressContext {
        tainted: true,
        seen_origin: true,
        ..EgressContext::default()
    }
}

#[test]
fn the_origin_key_is_the_scheme_host_and_effective_port_tuple() {
    // R3: the old seen-URL identity was host+path+query and dropped the
    // scheme and the port, so a clean fetch of `http://h/p` made
    // `https://h/p` an "exact re-fetch". The key is the full tuple now.
    assert_eq!(
        url_origin_key(&reqwest::Url::parse("http://h/p").unwrap()),
        "http://h:80"
    );
    assert_eq!(
        url_origin_key(&reqwest::Url::parse("https://h/p").unwrap()),
        "https://h:443"
    );
    assert_eq!(
        url_origin_key(&reqwest::Url::parse("http://h:8080/p").unwrap()),
        "http://h:8080"
    );
    assert_ne!(
        url_origin_key(&reqwest::Url::parse("http://h/p").unwrap()),
        url_origin_key(&reqwest::Url::parse("https://h/p").unwrap()),
        "scheme is part of the origin"
    );
    assert_ne!(
        url_origin_key(&reqwest::Url::parse("https://h:80/p").unwrap()),
        url_origin_key(&reqwest::Url::parse("https://h:443/p").unwrap()),
        "port 80 and port 443 are different origins"
    );
    assert_ne!(
        url_origin_key(&reqwest::Url::parse("https://h/p").unwrap()),
        url_origin_key(&reqwest::Url::parse("https://h:8443/p").unwrap()),
        "effective port is part of the origin"
    );
}

/// The sensitive-turn facts for `input` as if the conversation had seen
/// `seen_urls` (any URL on those origins). This models the engine's
/// origin-keyed set at the policy level.
fn ctx_seen_from(seen_urls: &[&str], input: &str, tainted: bool) -> EgressContext {
    let key = url_origin_key(&reqwest::Url::parse(input).unwrap());
    EgressContext {
        tainted,
        seen_origin: seen_urls
            .iter()
            .any(|url| url_origin_key(&reqwest::Url::parse(url).unwrap()) == key),
        ..EgressContext::default()
    }
}

#[test]
fn a_sensitive_turn_asks_for_every_fetch_of_a_seen_origin() {
    // R4: the bare-root exception is gone. Any silent request is a channel
    // (the origin observes whether the agent asked), so a seen origin buys
    // nothing on a sensitive turn: its bare root asks like everything else.
    let gate = web_gate(WebConfig {
        port_allowlist: vec![80, 443, 8443],
        ..WebConfig::default()
    });
    let seen = |input: &str| ctx_seen_from(&["https://h/page"], input, true);
    for url in [
        "https://h/",
        "http://h/",
        "https://h:8443/",
        "https://h/next",
        "https://h/?q=1",
        "https://h",
    ] {
        assert_eq!(
            gate.decide(url, &seen(url)),
            EgressDecision::Ask(AskReason::SensitiveTurn),
            "{url}"
        );
    }
    // A never-seen origin asks at the root too.
    assert_eq!(
        gate.decide(
            "https://other/",
            &EgressContext {
                tainted: true,
                ..EgressContext::default()
            }
        ),
        EgressDecision::Ask(AskReason::SensitiveTurn)
    );
}

#[test]
fn a_non_sensitive_turn_keeps_the_seen_origin_and_allowlist_rules() {
    // The redesign must not touch a clean turn: the modes and the
    // allowlist still decide, and a seen origin stays silent in
    // `open_read`/`ask_once_per_site`.
    let gate = web_gate(WebConfig {
        mode: WebMode::AskOncePerSite,
        ..WebConfig::default()
    });
    let seen = EgressContext {
        seen_origin: true,
        ..EgressContext::default()
    };
    assert_eq!(
        gate.decide("https://h/", &seen),
        EgressDecision::Allow,
        "a seen origin is still silent on a clean ask_once_per_site turn"
    );
    assert_eq!(
        gate.decide("https://h/deep/path?q=1", &seen),
        EgressDecision::Allow,
        "a clean turn has no path/query rule"
    );
    assert_eq!(
        gate.decide("https://new.example/", &EgressContext::default()),
        EgressDecision::Ask(AskReason::ModeAskOncePerSite)
    );
    let allowlisted = web_gate(WebConfig {
        mode: WebMode::AlwaysAsk,
        allow_domains: vec!["docs.rs".to_string()],
        ..WebConfig::default()
    });
    assert_eq!(
        allowlisted.decide("https://docs.rs/tokio", &EgressContext::default()),
        EgressDecision::Allow,
        "an allowlisted host is silent when the turn is not sensitive"
    );
}

#[test]
fn a_sensitive_turn_asks_to_refetch_a_seen_non_root_url() {
    // There is no exact-URL exception left: the URL that already ran is
    // model-composed egress the second time on a sensitive turn.
    let gate = web_gate(WebConfig::default());
    assert_eq!(
        gate.decide("https://h/page", &sensitive_seen()),
        EgressDecision::Ask(AskReason::SensitiveTurn)
    );
}

#[test]
fn a_path_carried_secret_on_a_seen_host_asks_while_sensitive() {
    // P3-1 (re-rated P2): a secret in the URL *path* must never leave on a
    // sensitive turn, whatever the host history.
    let gate = web_gate(WebConfig::default());
    let secret = "https://seen.example/log/GRID-CONTRACT-2026-AMOUNT-44000-EUROS";
    for sensitive in [
        EgressContext {
            tainted: true,
            seen_origin: true,
            ..EgressContext::default()
        },
        EgressContext {
            carries_private_data: true,
            seen_origin: true,
            ..EgressContext::default()
        },
    ] {
        assert_eq!(
            gate.decide(secret, &sensitive),
            EgressDecision::Ask(AskReason::SensitiveTurn),
            "a path-carried secret must ask on a sensitive turn"
        );
    }
    // A clean turn is unchanged: the seen origin still runs silently.
    let clean = EgressContext {
        seen_origin: true,
        ..EgressContext::default()
    };
    assert_eq!(gate.decide(secret, &clean), EgressDecision::Allow);
    // Percent-encoded spellings are a different path too.
    assert_eq!(
        gate.decide(
            "https://seen.example/log/GRID%2DCONTRACT%2D2026%2DAMOUNT",
            &EgressContext {
                tainted: true,
                seen_origin: true,
                ..EgressContext::default()
            }
        ),
        EgressDecision::Ask(AskReason::SensitiveTurn)
    );
}

#[test]
fn private_data_turn_asks_on_an_unseen_origin() {
    let gate = web_gate(WebConfig::default());
    let private = EgressContext {
        carries_private_data: true,
        ..EgressContext::default()
    };
    assert_eq!(
        gate.decide("https://evil.example/?d=secret", &private),
        EgressDecision::Ask(AskReason::SensitiveTurn)
    );
    // A clean turn in the default mode stays silent on an unseen origin.
    assert_eq!(
        gate.decide("https://evil.example/?d=secret", &EgressContext::default()),
        EgressDecision::Allow
    );
}

#[test]
fn a_model_authored_url_on_a_seen_origin_asks_while_sensitive() {
    let gate = web_gate(WebConfig::default());
    let sensitive_seen = sensitive_seen();
    assert_eq!(
        gate.decide("https://example.com/?d=notes", &sensitive_seen),
        EgressDecision::Ask(AskReason::SensitiveTurn)
    );
    // A different path is model-composed egress too, not just the query.
    assert_eq!(
        gate.decide("https://example.com/notes/secret", &sensitive_seen),
        EgressDecision::Ask(AskReason::SensitiveTurn)
    );
}

#[test]
fn modes_change_who_is_asked_never_the_gate() {
    // always_ask asks even on a seen, clean host.
    let gate = web_gate(WebConfig {
        mode: WebMode::AlwaysAsk,
        ..WebConfig::default()
    });
    assert_eq!(
        gate.decide(
            "https://example.com/",
            &EgressContext {
                seen_origin: true,
                ..EgressContext::default()
            }
        ),
        EgressDecision::Ask(AskReason::ModeAlwaysAsk)
    );
    // ask_once_per_site and smart have no memory/judge in W1: unseen asks.
    for (mode, reason) in [
        (WebMode::AskOncePerSite, AskReason::ModeAskOncePerSite),
        (WebMode::Smart, AskReason::SmartJudgeUnavailable),
    ] {
        let gate = web_gate(WebConfig {
            mode,
            ..WebConfig::default()
        });
        assert_eq!(
            gate.decide("https://example.com/", &EgressContext::default()),
            EgressDecision::Ask(reason),
            "{mode}"
        );
        // A denied URL is never asked about, whatever the mode.
        let gate = web_gate(WebConfig {
            mode,
            deny_domains: vec!["bad.example".to_string()],
            ..WebConfig::default()
        });
        assert_eq!(
            gate.decide("https://bad.example/", &EgressContext::default()),
            EgressDecision::Deny(DenyReason::DeniedDomain),
            "{mode}"
        );
    }
}

#[test]
fn allowlisted_hosts_are_silent_even_in_always_ask() {
    let gate = web_gate(WebConfig {
        mode: WebMode::AlwaysAsk,
        allow_domains: vec!["docs.rs".to_string()],
        ..WebConfig::default()
    });
    assert_eq!(
        gate.decide("https://docs.rs/tokio", &EgressContext::default()),
        EgressDecision::Allow
    );
}

#[test]
fn wb_smart_allows_a_seen_origin_without_a_judge() {
    // Smart with a seen origin allows; only the unseen case falls back to
    // Ask(SmartJudgeUnavailable).
    let gate = web_gate(WebConfig {
        mode: WebMode::Smart,
        ..WebConfig::default()
    });
    assert_eq!(
        gate.decide(
            "https://example.com/",
            &EgressContext {
                seen_origin: true,
                ..EgressContext::default()
            }
        ),
        EgressDecision::Allow
    );
}

#[test]
fn wb_decision_labels_are_stable_for_the_audit_row() {
    assert_eq!(AskReason::SensitiveTurn.as_str(), "sensitive_turn");
    assert_eq!(AskReason::ModeAlwaysAsk.as_str(), "mode_always_ask");
    assert_eq!(
        AskReason::ModeAskOncePerSite.as_str(),
        "mode_ask_once_per_site"
    );
    assert_eq!(
        AskReason::SmartJudgeUnavailable.as_str(),
        "smart_judge_unavailable"
    );
    assert_eq!(
        DenyReason::OriginNotApproved.to_string(),
        "origin_not_approved"
    );
    assert_eq!(DenyReason::ObfuscatedHost.to_string(), "obfuscated_host");
    assert_eq!(DenyReason::BudgetHost.to_string(), "budget_host");
    assert_eq!(EgressDecision::Allow.as_str(), "allow");
    assert_eq!(
        EgressDecision::Ask(AskReason::ModeAlwaysAsk).as_str(),
        "ask"
    );
    assert_eq!(EgressDecision::Deny(DenyReason::BudgetDay).as_str(), "deny");
    assert_eq!(BudgetKind::Host.deny_reason(), DenyReason::BudgetHost);
    assert_eq!(BudgetKind::Turn.deny_reason(), DenyReason::BudgetTurn);
    assert_eq!(BudgetKind::Day.deny_reason(), DenyReason::BudgetDay);
}

#[test]
fn an_allowlist_never_bypasses_the_sensitive_turn_ask_rule() {
    // The allowlisted-domain abuse (Cowork's own
    // allowlisted domain was used to exfiltrate) is why the sensitive-turn
    // rule runs before the allowlist, not after it. The allowlist exempts
    // a host from the *mode*, never from the sensitive-turn rule.
    for mode in [
        WebMode::OpenRead,
        WebMode::Smart,
        WebMode::AskOncePerSite,
        WebMode::AlwaysAsk,
    ] {
        let gate = web_gate(WebConfig {
            mode,
            allow_domains: vec!["docs.rs".to_string()],
            ..WebConfig::default()
        });
        // Taint: on an unseen, allowlisted origin the card is still asked.
        for sensitive in [
            EgressContext {
                tainted: true,
                ..EgressContext::default()
            },
            EgressContext {
                carries_private_data: true,
                ..EgressContext::default()
            },
        ] {
            assert_eq!(
                gate.decide("https://docs.rs/tokio", &sensitive),
                EgressDecision::Ask(AskReason::SensitiveTurn),
                "{mode}: allowlisted unseen origin on a sensitive turn must ask"
            );
        }
        // Once seen, a URL on the allowlisted origin still asks: the
        // sensitive-turn rule ignores the seen set entirely, so the bare
        // root asks too.
        let private_seen = EgressContext {
            carries_private_data: true,
            seen_origin: true,
            ..EgressContext::default()
        };
        assert_eq!(
            gate.decide("https://docs.rs/?d=private-notes", &private_seen),
            EgressDecision::Ask(AskReason::SensitiveTurn),
            "{mode}: model-composed query on the allowlisted origin"
        );
        assert_eq!(
            gate.decide("https://docs.rs/tokio", &private_seen),
            EgressDecision::Ask(AskReason::SensitiveTurn),
            "{mode}: model-composed path on the allowlisted origin"
        );
        assert_eq!(
            gate.decide("https://docs.rs/", &private_seen),
            EgressDecision::Ask(AskReason::SensitiveTurn),
            "{mode}: even the bare root of the allowlisted origin asks"
        );
    }
}
