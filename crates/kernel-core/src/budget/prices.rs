//! Per-model prices used to record `usd_cents` spend.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Price of one model, in **whole cents per million tokens**.
///
/// Integer cents keep the ledger's `usd_cents` arithmetic exact; per-call
/// costs are rounded **up** to the next cent so a stream of small calls can
/// never slip under the money cap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelPrice {
    /// Cents charged per million input tokens.
    pub input_cents_per_million: u64,
    /// Cents charged per million output tokens.
    pub output_cents_per_million: u64,
}

/// Per-model price table (`[prices.models.<model>]` in `config.toml`).
///
/// Used to turn provider-reported tokens into recorded `usd_cents` spend so
/// the daily money cap can bind. A model the table does not know records no
/// money (the engine logs one notice: token caps are the effective ones).
/// The built-in defaults cover the models this installation uses; the owner
/// can override or extend them in config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PriceTable {
    /// Model id (`ProviderConfig::model`) to price.
    pub models: HashMap<String, ModelPrice>,
}

impl Default for PriceTable {
    /// Built-in prices for the models this installation is documented to use
    /// (cents per million tokens).
    fn default() -> Self {
        let mut models = HashMap::new();
        for (model, input, output) in [
            // DeepSeek via opencode-go / OpenCode Zen (no retention).
            ("deepseek-v4-flash", 14, 28),
            ("deepseek-v4.1-flash", 14, 28),
            ("deepseek-v4-pro", 174, 348),
            // DeepSeek direct list price (the pre-migration config).
            ("deepseek-flash", 22, 66),
            // Other families seen in the fleet.
            ("minimax-m3", 30, 120),
            ("gpt-6-luna", 10, 50),
        ] {
            models.insert(
                model.to_string(),
                ModelPrice {
                    input_cents_per_million: input,
                    output_cents_per_million: output,
                },
            );
        }
        Self { models }
    }
}

impl PriceTable {
    /// Price for `model`, when the table knows it.
    pub fn price(&self, model: &str) -> Option<&ModelPrice> {
        self.models.get(model)
    }

    /// Cost of one call in cents, rounded up; `0` when the model is unknown
    /// (the engine logs a one-time notice: the `usd_cents` cap cannot bind
    /// and the token caps are the effective ones).
    pub fn usd_cents_for(&self, model: Option<&str>, tokens_in: u64, tokens_out: u64) -> u64 {
        let Some(price) = model.and_then(|model| self.models.get(model)) else {
            return 0;
        };
        let numerator = tokens_in as u128 * price.input_cents_per_million as u128
            + tokens_out as u128 * price.output_cents_per_million as u128;
        numerator.div_ceil(1_000_000).min(u64::MAX as u128) as u64
    }
}
