//! Daily caps for one agent and the `[budgets]` section.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::limits::{
    conservative_limit, DEFAULT_DAILY_TOKENS_IN, DEFAULT_DAILY_TOKENS_OUT, DEFAULT_DAILY_USD_CENTS,
};
use super::usage::UsageKind;

/// Serde helper: omit `false` flags from a serialized config.
fn is_false(value: &bool) -> bool {
    !*value
}

/// Daily caps for one agent. Unset fields mean "no cap".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BudgetCaps {
    /// Maximum input tokens per day.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_in: Option<u64>,
    /// Maximum output tokens per day.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_out: Option<u64>,
    /// Maximum spend in cents per day.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usd_cents: Option<u64>,
    /// Maximum connector (MCP) tool calls per day (S2b). An unset or `0`
    /// field falls back to [`DEFAULT_DAILY_CONNECTOR_CALLS`](super::limits::DEFAULT_DAILY_CONNECTOR_CALLS) like the provider
    /// kinds; the connector meter is the only consumer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_calls: Option<u64>,
    /// Explicit opt-out: **no** daily cap for this agent. Logged loudly when
    /// used; the default config never sets it.
    #[serde(skip_serializing_if = "is_false")]
    pub unlimited: bool,
}

impl BudgetCaps {
    /// The conservative caps a fresh install runs under: a runaway turn loop
    /// cannot spend more than a few cents a day until the owner raises them
    /// in `[budgets]`.
    pub fn conservative_default() -> Self {
        Self {
            tokens_in: Some(DEFAULT_DAILY_TOKENS_IN),
            tokens_out: Some(DEFAULT_DAILY_TOKENS_OUT),
            usd_cents: Some(DEFAULT_DAILY_USD_CENTS),
            // Left unset so a fresh config.toml gains no new key; the effective
            // cap still comes from `conservative_limit` via `limit()`.
            connector_calls: None,
            unlimited: false,
        }
    }

    /// Cap for one kind: the configured value, or the conservative default
    /// when the field is absent or a `0` placeholder. Only an explicit
    /// `unlimited = true` removes the cap entirely.
    pub fn limit(&self, kind: UsageKind) -> Option<u64> {
        if self.unlimited {
            return None;
        }
        let configured = match kind {
            UsageKind::TokensIn => self.tokens_in,
            UsageKind::TokensOut => self.tokens_out,
            UsageKind::UsdCents => self.usd_cents,
            UsageKind::ConnectorCalls => self.connector_calls,
        };
        Some(
            configured
                .filter(|value| *value > 0)
                .unwrap_or_else(|| conservative_limit(kind)),
        )
    }

    /// True when no kind has an explicit value in this set. Note that an
    /// "unset" set still *enforces* the conservative defaults: only
    /// [`Self::unlimited`] turns enforcement off.
    pub fn is_unset(&self) -> bool {
        self.tokens_in.is_none()
            && self.tokens_out.is_none()
            && self.usd_cents.is_none()
            && self.connector_calls.is_none()
    }

    /// True only for the explicit opt-out. An all-unset cap set is **not**
    /// unlimited: it enforces the conservative defaults, so the only
    /// way to opt out is to write `unlimited = true` (which the daemon logs
    /// loudly).
    pub fn is_unlimited(&self) -> bool {
        self.unlimited
    }

    /// `self` with `overrides` applied on top, field by field.
    pub fn merged_with(&self, overrides: &BudgetCaps) -> BudgetCaps {
        BudgetCaps {
            tokens_in: overrides.tokens_in.or(self.tokens_in),
            tokens_out: overrides.tokens_out.or(self.tokens_out),
            usd_cents: overrides.usd_cents.or(self.usd_cents),
            connector_calls: overrides.connector_calls.or(self.connector_calls),
            unlimited: self.unlimited || overrides.unlimited,
        }
    }
}

/// The `[budgets]` section: defaults plus per-agent overrides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Budgets {
    /// Caps that apply to every agent unless overridden. Missing or partial
    /// sections keep the conservative defaults (see
    /// [`BudgetCaps::conservative_default`]) — "no cap" is no longer the
    /// silent default.
    #[serde(default = "BudgetCaps::conservative_default")]
    pub default: BudgetCaps,
    /// Per-agent overrides; fields left unset fall back to `default`. Read from
    /// the legacy `[budgets.dots]` table too.
    #[serde(skip_serializing_if = "HashMap::is_empty", alias = "dots")]
    pub agents: HashMap<String, BudgetCaps>,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            default: BudgetCaps::conservative_default(),
            agents: HashMap::new(),
        }
    }
}

impl Budgets {
    /// Effective caps for `agent`: the agent's overrides merged onto the defaults.
    pub fn caps_for(&self, agent: &str) -> BudgetCaps {
        match self.agents.get(agent) {
            Some(overrides) => self.default.merged_with(overrides),
            None => self.default,
        }
    }

    /// True when no agent has any cap configured.
    pub fn is_unset(&self) -> bool {
        self.default.is_unset() && self.agents.values().all(BudgetCaps::is_unset)
    }
}
