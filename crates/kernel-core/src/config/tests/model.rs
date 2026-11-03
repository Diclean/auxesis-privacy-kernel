//! Tests for the config defaults, the time bounds and the budgets.

use super::super::*;
use tempfile::tempdir;

#[test]
fn parses_the_context_window_and_turn_timeout() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "turn_timeout_secs = 42\n[context]\nmax_messages = 7\nmax_tokens = 900\n",
    )
    .unwrap();

    let config = Config::load_or_create(&path).unwrap();
    assert_eq!(config.turn_timeout_secs, 42);
    assert_eq!(config.turn_timeout().as_secs(), 42);
    assert_eq!(config.context.max_messages, 7);
    assert_eq!(config.context.max_tokens, 900);

    // A zero timeout falls back to the default instead of disabling it.
    let zero: Config = toml::from_str("turn_timeout_secs = 0\n").unwrap();
    assert_eq!(zero.turn_timeout().as_secs(), DEFAULT_TURN_TIMEOUT_SECS);
}

#[test]
fn approvals_default_to_auto_and_parse_ask() {
    let parsed: Config = toml::from_str("version = 1\n").unwrap();
    assert_eq!(parsed.approvals, ApprovalMode::Auto);
    let ask: Config = toml::from_str("approvals = \"ask\"\n").unwrap();
    assert_eq!(ask.approvals, ApprovalMode::Ask);
    // No "full access" level: an unknown value does not parse.
    assert!(toml::from_str::<Config>("approvals = \"full\"\n").is_err());
    let written = toml::to_string(&Config::default()).unwrap();
    assert!(written.contains("approvals = \"auto\""), "{written}");
}

#[test]
fn calibration_turn_timeout_default_is_pinned() {
    // H-05: the default turn cap is 1800 s, and a config that says
    // nothing still gets it (the field keeps `serde(default)`).
    assert_eq!(DEFAULT_TURN_TIMEOUT_SECS, 1800);
    assert_eq!(Config::default().turn_timeout().as_secs(), 1800);
    let parsed: Config = toml::from_str("version = 1\n").unwrap();
    assert_eq!(parsed.turn_timeout().as_secs(), 1800);
}

#[test]
fn calibration_approval_timeout_defaults_and_parses() {
    // H-04: 600 s by default, owner-tunable through `[approval]`.
    assert_eq!(DEFAULT_APPROVAL_TIMEOUT_SECS, 600);
    let config = Config::default();
    assert_eq!(config.approval.timeout_secs, 600);
    assert_eq!(config.approval_timeout().as_secs(), 600);

    assert!(config.approval.shell_judge, "the judge is on by default");
    for (raw, on) in [
        ("false", false),
        ("true", true),
        ("\"yes\"", false),
        ("1", false),
    ] {
        let parsed: Config = toml::from_str(&format!("[approval]\nshell_judge = {raw}\n")).unwrap();
        assert_eq!(parsed.approval.shell_judge, on, "{raw}");
    }
    let parsed: Config = toml::from_str("[approval]\ntimeout_secs = 120\n").unwrap();
    assert_eq!(parsed.approval.timeout_secs, 120);
    assert_eq!(parsed.approval_timeout().as_secs(), 120);

    // A zero falls back to the default instead of disabling the wait.
    let zero: Config = toml::from_str("[approval]\ntimeout_secs = 0\n").unwrap();
    assert_eq!(zero.approval_timeout().as_secs(), 600);

    // Unknown keys are rejected (a typo must not silently change the
    // fail-closed bound).
    let err = toml::from_str::<Config>("[approval]\ntimeout = 60\n").unwrap_err();
    assert!(err.to_string().contains("timeout"), "{err}");
}

#[test]
fn the_approval_timeout_is_clamped_strictly_below_the_turn_timeout() {
    // H-04: the turn must be able to report the approval denial, so the
    // approval wait never reaches the turn timeout; expiry stays DENY.
    let config: Config =
        toml::from_str("turn_timeout_secs = 100\n[approval]\ntimeout_secs = 600\n").unwrap();
    assert_eq!(config.approval_timeout().as_secs(), 99);
    assert_eq!(config.turn_timeout().as_secs(), 100);

    // Exactly equal is clamped too ("strictly below").
    let config: Config =
        toml::from_str("turn_timeout_secs = 100\n[approval]\ntimeout_secs = 100\n").unwrap();
    assert_eq!(config.approval_timeout().as_secs(), 99);

    // A one-second turn timeout cannot drive the wait to zero (a zero
    // wait would be an instant deny, which is a different behaviour).
    let config: Config = toml::from_str("turn_timeout_secs = 1\n").unwrap();
    assert_eq!(config.approval_timeout().as_secs(), 1);

    // The default pair: 600 < 1800, no clamp involved.
    let config = Config::default();
    assert!(config.approval_timeout() < config.turn_timeout());
}

#[test]
fn parses_the_budgets_section() {
    use crate::budget::{BudgetCaps, UsageKind};

    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        r#"
            version = 1
            log_level = "info"
            default_agent = "main"

            [budgets.default]
            tokens_in = 1000
            usd_cents = 25

            [budgets.agents.axis]
            tokens_in = 5
            tokens_out = 2
            "#,
    )
    .unwrap();

    let config = Config::load_or_create(&path).unwrap();
    assert_eq!(
        config.budgets.default,
        BudgetCaps {
            tokens_in: Some(1000),
            tokens_out: None,
            usd_cents: Some(25),
            connector_calls: None,
            unlimited: false,
        }
    );
    let axis = config.budgets.caps_for("axis");
    assert_eq!(axis.limit(UsageKind::TokensIn), Some(5));
    assert_eq!(axis.limit(UsageKind::TokensOut), Some(2));
    assert_eq!(axis.limit(UsageKind::UsdCents), Some(25));
    let main = config.budgets.caps_for("main");
    assert_eq!(main.limit(UsageKind::TokensIn), Some(1000));
    assert_eq!(
        main.limit(UsageKind::TokensOut),
        Some(crate::budget::DEFAULT_DAILY_TOKENS_OUT),
        "an absent field falls back to the conservative default"
    );
}

#[test]
fn an_old_config_with_an_empty_budgets_table_is_migrated_to_caps() {
    // Migration shape: the exact table header an old install wrote, plus
    // a per-agent override. Loading it must yield effective caps, not
    // `is_unlimited`.
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        r#"
            version = 1
            default_agent = "main"

            [budgets.default]

            [budgets.agents.axis]
            tokens_in = 7
            "#,
    )
    .unwrap();

    let config = Config::load_or_create(&path).unwrap();
    let main = config.budgets.caps_for("main");
    assert!(!main.is_unlimited());
    assert_eq!(
        main.limit(crate::budget::UsageKind::TokensIn),
        Some(crate::budget::DEFAULT_DAILY_TOKENS_IN)
    );
    assert_eq!(
        main.limit(crate::budget::UsageKind::UsdCents),
        Some(crate::budget::DEFAULT_DAILY_USD_CENTS)
    );
    let axis = config.budgets.caps_for("axis");
    assert_eq!(axis.limit(crate::budget::UsageKind::TokensIn), Some(7));
    assert_eq!(
        axis.limit(crate::budget::UsageKind::TokensOut),
        Some(crate::budget::DEFAULT_DAILY_TOKENS_OUT)
    );

    // The only opt-out is explicit, and it is per agent.
    std::fs::write(&path, "version = 1\n[budgets.default]\nunlimited = true\n").unwrap();
    let opted_out = Config::load_or_create(&path).unwrap();
    assert!(opted_out.budgets.caps_for("main").is_unlimited());
    for kind in crate::budget::UsageKind::ALL {
        assert_eq!(opted_out.budgets.caps_for("main").limit(kind), None);
    }
}
