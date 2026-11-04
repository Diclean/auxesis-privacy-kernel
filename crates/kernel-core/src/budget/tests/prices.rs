//! Tests for the model price table.

use super::super::*;

#[test]
fn price_table_prices_the_owner_models_and_rounds_up() {
    let prices = PriceTable::default();
    // DeepSeek V4 Flash (legacy id, billed as Flash): 30 / 120 cents per million.
    let price = prices.price("deepseek-v4-flash").expect("built-in price");
    assert_eq!(price.input_cents_per_million, 30);
    assert_eq!(price.output_cents_per_million, 120);
    // 50k input at 30 cents/M = 1.5 cents -> 2 (never under-count).
    assert_eq!(
        prices.usd_cents_for(Some("deepseek-v4-flash"), 50_000, 0),
        2
    );
    assert_eq!(
        prices.usd_cents_for(Some("deepseek-v4-flash"), 0, 1_000_000),
        120
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
fn deepseek_flash_costs_deepseeks_peak_price() {
    // DeepSeek's pricing page, peak hours, cache miss: $0.30 in, $1.20 out
    // per million tokens. The old 22 / 66 let the money cap bind late.
    let prices = PriceTable::default();
    assert_eq!(
        prices.price("deepseek-flash"),
        Some(&ModelPrice {
            input_cents_per_million: 30,
            output_cents_per_million: 120,
        })
    );
    assert_eq!(
        prices.usd_cents_for(Some("deepseek-flash"), 1_000_000, 1_000_000),
        150
    );
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
