//! Approval settings, the approval mode and the fail-closed timeout.

use super::model::Config;
use serde::{Deserialize, Serialize};

/// Default wait before an unanswered approval is denied (`[approval]
/// timeout_secs`). Calibration H-04: long enough for a human to notice the
/// card during daily use; the turn timeout still bounds it (see
/// [`Config::approval_timeout`]).
pub const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 600;

/// The top-level `approvals` setting. There is no "full access" level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalMode {
    /// Clean, sandboxed, local calls and `delegate` run without a card.
    #[default]
    Auto,
    /// Every ask shows a card (the behaviour before APPROVAL-MODES).
    Ask,
}

/// Interactive approval settings (`[approval]` in `config.toml`).
///
/// The approval timeout is a **fail-closed** bound: an unanswered card is a
/// deny (H-04 keeps that). What changed is the value and where it comes
/// from — 600 s by default, owner-tunable, and always strictly below the
/// turn timeout so the turn can still report the denial instead of being
/// killed first ([`Config::approval_timeout`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalConfig {
    /// Seconds an unanswered approval may wait before the fail-closed deny.
    /// `0` falls back to [`DEFAULT_APPROVAL_TIMEOUT_SECS`]. Clamped strictly
    /// below the turn timeout (see [`Config::approval_timeout`]).
    pub timeout_secs: u64,
    /// SHELL-JUDGE: under `approvals = "auto"`, a clean, sandboxed `shell`
    /// ask with the network off goes to a judge model before the card (default
    /// true). A value that is not a boolean turns it off.
    #[serde(deserialize_with = "bool_or_off")]
    pub shell_judge: bool,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_APPROVAL_TIMEOUT_SECS,
            shell_judge: true,
        }
    }
}

/// A boolean, or `false` for any other value: a mistyped switch fails closed.
fn bool_or_off<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Lenient {
        Bool(bool),
        Other(serde::de::IgnoredAny),
    }
    Ok(matches!(
        Lenient::deserialize(deserializer)?,
        Lenient::Bool(true)
    ))
}

impl Config {
    /// The approval wait, never zero and always **strictly below** the turn
    /// timeout (H-04).
    ///
    /// An unanswered approval is a deny either way; the clamp only decides
    /// which bound reports it. If the approval timeout reached or crossed
    /// the turn timeout, the turn would be cancelled first and the denial
    /// would surface as a generic `504 turn_timeout` instead of the
    /// approval's own expiry (and the card would be retired as abandoned).
    /// A `0` in the file falls back to the default; a value at or above the
    /// turn timeout is clamped to one second below it. The result is never
    /// below one second, so a hand-edited config cannot disable the wait.
    pub fn approval_timeout(&self) -> std::time::Duration {
        let configured = if self.approval.timeout_secs == 0 {
            DEFAULT_APPROVAL_TIMEOUT_SECS
        } else {
            self.approval.timeout_secs
        };
        let turn_secs = self.turn_timeout().as_secs();
        // Strictly below the turn timeout, and never below one second.
        let secs = configured.min(turn_secs.saturating_sub(1)).max(1);
        std::time::Duration::from_secs(secs)
    }
}
