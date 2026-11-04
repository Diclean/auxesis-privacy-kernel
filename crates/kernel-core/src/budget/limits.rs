//! Default daily caps and the warning line shared by every budget layer.

use super::usage::UsageKind;

/// Unit marker for token amounts derived from text length instead of
/// provider-reported `usage` (providers that do not report usage).
pub const ESTIMATED_UNIT: &str = "tokens_est";

/// Default daily input-token cap for every agent when the config says nothing.
///
/// Calibration: the owner chose 2,000,000 input tokens/day — the
/// previous 100,000 was hit during ordinary daily use. The shape of the cap
/// (reservation, latch, warning, explicit `unlimited` opt-out) is unchanged.
pub const DEFAULT_DAILY_TOKENS_IN: u64 = 2_000_000;

/// Default daily output-token cap for every agent when the config says nothing.
///
/// Calibration: raised with the input cap (400,000 output tokens/day).
pub const DEFAULT_DAILY_TOKENS_OUT: u64 = 400_000;

/// Default daily spend cap (cents) for every agent when the config says nothing.
///
/// Calibration: 500 cents/day (the previous 50 cents/day was reached
/// during ordinary daily use).
pub const DEFAULT_DAILY_USD_CENTS: u64 = 500;

/// Default daily **connector-call** cap for every agent when the config says
/// nothing.
///
/// Connector calls do not spend provider tokens; they are a separate resource
/// dimension (the `connector_calls` [`UsageKind`]) metered by the connector
/// layer. Like the provider kinds, an unset or `0` field still falls back to a
/// conservative daily cap so a runaway tool loop cannot call a remote service
/// unbounded. The provider budget guard and the spend-reservation ledger are
/// deliberately unaware of this kind (they iterate [`UsageKind::PROVIDER`]),
/// so adding it cannot gate an ordinary provider call.
pub const DEFAULT_DAILY_CONNECTOR_CALLS: u64 = 500;

/// Fraction of a cap (8/10 = 80 %) at which a `budget.warning` event is
/// emitted, once per kind/day, before the day latches closed.
pub const WARNING_NUMERATOR: u64 = 8;
/// Denominator of [`WARNING_NUMERATOR`].
pub const WARNING_DENOMINATOR: u64 = 10;

/// The usage line at which `limit` starts warning (used by the store's
/// settle path and kept here so every layer warns at the same point).
pub fn warning_threshold(limit: u64) -> u64 {
    (limit as u128 * WARNING_NUMERATOR as u128 / WARNING_DENOMINATOR as u128) as u64
}

/// Conservative daily cap for one kind, applied when a config does not say
/// otherwise (absent field, empty `[budgets.default]` table, or a `0`
/// placeholder). This keeps an **existing** installation capped after an
/// upgrade: `serde(default)` only fires for a missing key, never for an
/// empty table an old config already carries.
pub(crate) fn conservative_limit(kind: UsageKind) -> u64 {
    match kind {
        UsageKind::TokensIn => DEFAULT_DAILY_TOKENS_IN,
        UsageKind::TokensOut => DEFAULT_DAILY_TOKENS_OUT,
        UsageKind::UsdCents => DEFAULT_DAILY_USD_CENTS,
        UsageKind::ConnectorCalls => DEFAULT_DAILY_CONNECTOR_CALLS,
    }
}
