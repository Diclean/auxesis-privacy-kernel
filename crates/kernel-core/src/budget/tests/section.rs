//! Tests for parsing and serializing the `[budgets]` section.

use std::collections::HashMap;

use super::super::*;
use super::support::caps;

#[test]
fn config_toml_parses_defaults_and_overrides() {
    let budgets: Budgets = toml::from_str(
        r#"
            [default]
            tokens_in = 100
            tokens_out = 50

            [agents.main]
            tokens_in = 5
            "#,
    )
    .unwrap();

    assert_eq!(budgets.default, caps(Some(100), Some(50), None));
    assert_eq!(budgets.caps_for("main"), caps(Some(5), Some(50), None));
    assert_eq!(budgets.caps_for("axis"), caps(Some(100), Some(50), None));
}

#[test]
fn legacy_dots_table_still_loads_as_agents() {
    // Configs written before the rename keep their `[budgets.dots.*]` caps.
    let budgets: Budgets = toml::from_str("[dots.main]\ntokens_in = 5\n").unwrap();
    assert_eq!(budgets.agents["main"], caps(Some(5), None, None));
}

#[test]
fn unknown_budget_keys_are_rejected() {
    // A typo'd cap must fail loudly instead of silently disabling spend
    // control (`token_in` is not `tokens_in`).
    let err = toml::from_str::<Budgets>("token_in = 5\n").unwrap_err();
    assert!(err.to_string().contains("token_in"), "{err}");

    let err = toml::from_str::<Budgets>("[default]\ntoken_in = 5\n").unwrap_err();
    assert!(err.to_string().contains("token_in"), "{err}");

    let err = toml::from_str::<Budgets>("[agents.main]\ntokenss_in = 5\n").unwrap_err();
    assert!(err.to_string().contains("tokenss_in"), "{err}");
}

#[test]
fn budgets_serialize_back_to_toml() {
    let mut budgets = Budgets {
        default: caps(Some(100), None, None),
        agents: HashMap::new(),
    };
    budgets
        .agents
        .insert("main".to_string(), caps(Some(5), None, None));

    let text = toml::to_string(&budgets).unwrap();
    let back: Budgets = toml::from_str(&text).unwrap();
    assert_eq!(back, budgets);
}
