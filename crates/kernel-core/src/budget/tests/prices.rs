//! Tests for the model price table.

use super::super::*;

#[test]
fn price_table_prices_the_owner_models_and_rounds_up() {
    let prices = PriceTable::default();
    // DeepSeek V4 Flash via opencode-go/Zen: 14 / 28 cents per million.
    let price = prices.price("deepseek-v4-flash").expect("built-in price");
    assert_eq!(price.input_cents_per_million, 14);
    assert_eq!(price.output_cents_per_million, 28);
    // 100k input at 14 cents/M = 1.4 cents -> 2 (never under-count).
    assert_eq!(
        prices.usd_cents_for(Some("deepseek-v4-flash"), 100_000, 0),
        2
    );
    assert_eq!(
        prices.usd_cents_for(Some("deepseek-v4-flash"), 0, 1_000_000),
        28
    );
    // Exactly one million input cents-wise stays exact.
    assert_eq!(
        prices.usd_cents_for(Some("deepseek-v4-pro"), 1_000_000, 0),
        174
    );
    // Unknown or missing models record nothing.
    assert_eq!(prices.usd_cents_for(None, 10_000, 10_000), 0);
    assert_eq!(prices.usd_cents_for(Some("ghost-model"), 10_000, 0), 0);
}

#[test]
fn price_table_parses_per_model_overrides() {
    let prices: PriceTable = toml::from_str(
        r#"
        [models.my-local]
        input_cents_per_million = 0
        output_cents_per_million = 1
        "#,
    )
    .unwrap();
    assert_eq!(prices.models.len(), 1, "the config replaces the defaults");
    assert_eq!(prices.usd_cents_for(Some("my-local"), 0, 2_000_000), 2);
    // A config without `[prices]` uses the built-ins.
    let config: crate::Config = toml::from_str("version = 1\n").unwrap();
    assert!(config.prices.price("deepseek-v4-flash").is_some());
}
