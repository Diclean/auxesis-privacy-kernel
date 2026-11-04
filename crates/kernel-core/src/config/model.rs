//! The top-level [`Config`] type, its defaults and its turn timeout.

use super::acp::AcpConfig;
use super::approval::{ApprovalConfig, ApprovalMode};
use super::context::ContextConfig;
use super::sections::{
    BriefConfig, LocationConfig, MemoryConfig, QuietConfig, TelegramConfig, UiConfig,
};
use super::shell::ShellConfig;
use super::web::WebConfig;
use crate::budget::{Budgets, PriceTable};
use crate::privacy::PrivacyConfig;
use serde::{Deserialize, Serialize};

/// Default hard cap on one API turn (`POST /v1/threads/{id}/messages`).
///
/// Calibration: 1,800 s. The previous 300 s cut real work (long tool
/// loops, slow providers) mid-turn; the cap still exists, it is just no
/// longer the first thing that fires.
pub const DEFAULT_TURN_TIMEOUT_SECS: u64 = 1800;

/// Top-level configuration (`~/.auxesis/config.toml`).
///
/// Missing fields are filled with defaults, so older configs keep working
/// when new fields are added.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Config format version.
    pub version: u32,
    /// Default log level (`error`, `warn`, `info`, `debug`, `trace`).
    pub log_level: String,
    /// Name of the default agent the CLI talks to. Read from the legacy
    /// `default_dot` key too.
    #[serde(alias = "default_dot")]
    pub default_agent: String,
    /// Per-agent daily caps over recorded provider usage (`[budgets]`).
    ///
    /// Absent fields keep the conservative defaults: a fresh install is
    /// capped, never silently unlimited. An empty `[budgets.default]` table
    /// (what every older config carries) also keeps them.
    pub budgets: Budgets,
    /// Per-model prices (`[prices.models.<model>]`), in whole cents per
    /// million tokens. Used to record `usd_cents` spend from token counts
    /// when the provider does not report a cost, so the daily money cap can
    /// bind. Absent: the built-in prices for the documented models.
    pub prices: PriceTable,
    /// Shell tool sandbox settings (`[shell]`).
    pub shell: ShellConfig,
    /// Model-context window (`[context]`).
    pub context: ContextConfig,
    /// Interactive approval settings (`[approval]`).
    pub approval: ApprovalConfig,
    /// Approval mode (`approvals = "auto" | "ask"`), `auto` when absent.
    /// `auto` approves reads, clean sandboxed calls and the chief's
    /// `delegate` without a card; sends, deletes, payments, unsandboxed or
    /// tainted calls and explicit `[[rules]]` still decide. `ask` is the
    /// card for every ask.
    pub approvals: ApprovalMode,
    /// ACP agent backends (`[acp]`), off by default (they ship behind a
    /// flag until the security review passes).
    pub acp: AcpConfig,
    /// Web egress policy (`[web]`). A GET is egress, not a local read.
    pub web: WebConfig,
    /// Morning brief settings (`[brief]`), disabled by default.
    pub brief: BriefConfig,
    /// Owner-selected city (`[location]`).
    pub location: LocationConfig,
    /// Memory behavior (`[memory]`).
    pub memory: MemoryConfig,
    /// User interface language (`[ui].language`), used by background sends.
    pub ui: UiConfig,
    /// Local quiet window (`[quiet]`).
    pub quiet: QuietConfig,
    /// Hard cap on one API turn, in seconds (default
    /// [`DEFAULT_TURN_TIMEOUT_SECS`]). `0` falls back to the default.
    pub turn_timeout_secs: u64,
    /// Telegram bot channel settings (`[telegram]`), disabled by default.
    pub telegram: TelegramConfig,
    /// Global privacy mode (`[privacy]`), private by default. See `crate::privacy`.
    pub privacy: PrivacyConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            log_level: "info".to_string(),
            // The chief: the owner talks to Aux, which
            // delegates to the domain agents.
            default_agent: "aux".to_string(),
            // The default posture is capped, not unlimited. The values
            // are documented in `budget::BudgetCaps::conservative_default`.
            budgets: Budgets::default(),
            prices: PriceTable::default(),
            shell: ShellConfig::default(),
            context: ContextConfig::default(),
            approval: ApprovalConfig::default(),
            approvals: ApprovalMode::default(),
            acp: AcpConfig::default(),
            web: WebConfig::default(),
            brief: BriefConfig::default(),
            location: LocationConfig::default(),
            memory: MemoryConfig::default(),
            ui: UiConfig::default(),
            quiet: QuietConfig::default(),
            turn_timeout_secs: DEFAULT_TURN_TIMEOUT_SECS,
            telegram: TelegramConfig::default(),
            privacy: PrivacyConfig::default(),
        }
    }
}

impl Config {
    /// The API turn timeout, never zero (a zero in a hand-edited file falls
    /// back to the default instead of disabling the cap).
    pub fn turn_timeout(&self) -> std::time::Duration {
        let secs = if self.turn_timeout_secs == 0 {
            DEFAULT_TURN_TIMEOUT_SECS
        } else {
            self.turn_timeout_secs
        };
        std::time::Duration::from_secs(secs)
    }
}
