//! Start errors and per-server status types for the MCP runtime.

use std::fmt;
use std::time::Duration;

use crate::limits::CALL_TOOL_TIMEOUT;

/// Whole-server discovery budget at daemon startup (one server).
pub const STARTUP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
/// Most `tools/list` resume rounds a startup discovery follows.
pub const MAX_DISCOVERY_ROUNDS: usize = 4;
/// Budget for one dotted tool call.
pub const MCP_CALL_TIMEOUT: Duration = CALL_TOOL_TIMEOUT;

/// Why one configured server did not start.
///
/// Every variant is content-free: only ids, environment **names** and fixed
/// labels, never a server-supplied string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpStartError {
    /// A declared `env` name had no value in `~/.auxesis/.env`.
    MissingSecret {
        /// The missing variable name.
        name: String,
    },
    /// The pinned launch command was refused.
    Command(&'static str),
    /// The transport could not be built.
    Transport(&'static str),
    /// `initialize` or `tools/list` failed.
    Discovery(&'static str),
    /// The mandatory macOS stdio sandbox is unavailable (item 8).
    SandboxUnavailable,
    /// The whole discovery crossed [`STARTUP_DISCOVERY_TIMEOUT`].
    Timeout,
}

impl McpStartError {
    /// A stable, content-free classification for status and logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::MissingSecret { .. } => "missing_secret",
            Self::Command(_) => "command_refused",
            Self::Transport(_) => "transport_unavailable",
            Self::Discovery(_) => "discovery_failed",
            Self::SandboxUnavailable => "sandbox_unavailable",
            Self::Timeout => "timeout",
        }
    }
}

impl fmt::Display for McpStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSecret { name } => write!(f, "missing secret `{name}`"),
            Self::Command(label) => write!(f, "invalid stdio command ({label})"),
            Self::Transport(kind) => write!(f, "transport unavailable ({kind})"),
            Self::Discovery(kind) => write!(f, "discovery failed ({kind})"),
            Self::SandboxUnavailable => f.write_str("stdio sandbox unavailable"),
            Self::Timeout => f.write_str("discovery timed out"),
        }
    }
}

/// Lifecycle state of one configured server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpServerState {
    /// Discovery completed.
    Ready,
    /// `enabled = false`.
    Disabled,
    /// An uncurated `stdio` server whose exact launch has not been confirmed by
    /// the owner. It is quarantined (never spawned) until it is.
    NeedsConfirmation,
    /// The entry is unusable (a hard-refused launch, a catalog mismatch, a
    /// legacy shape). It is quarantined one by one; other servers still load.
    Quarantined,
    /// Discovery failed (isolated; the daemon keeps running).
    Failed,
}

impl McpServerState {
    /// Stable lowercase label used by the CLI and audit rows.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Disabled => "disabled",
            Self::NeedsConfirmation => "needs_confirmation",
            Self::Quarantined => "quarantined",
            Self::Failed => "failed",
        }
    }
}

/// A refusal the caller's policy applies before any transport is built.
///
/// The `reason` is a fixed, content-free label (shown in the API and UI);
/// `state` distinguishes "needs the owner's confirmation" from "unusable".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerRefusal {
    /// Lifecycle state to report for the refused server.
    pub state: McpServerState,
    /// Stable, content-free reason label.
    pub reason: &'static str,
}

impl McpServerRefusal {
    /// An uncurated `stdio` server that needs the owner's confirmation.
    pub fn needs_confirmation(reason: &'static str) -> Self {
        Self {
            state: McpServerState::NeedsConfirmation,
            reason,
        }
    }

    /// An unusable entry (catalog mismatch, hard refusal, legacy shape).
    pub fn quarantined(reason: &'static str) -> Self {
        Self {
            state: McpServerState::Quarantined,
            reason,
        }
    }

    /// A server the policy allowed but that failed before discovery (for
    /// example an egress refusal).
    pub fn failed(reason: &'static str) -> Self {
        Self {
            state: McpServerState::Failed,
            reason,
        }
    }
}

/// One server's status, with no tool content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerStatus {
    /// Configured id.
    pub id: String,
    /// `http` / `stdio`.
    pub transport: &'static str,
    /// Whether the file enabled it.
    pub enabled: bool,
    /// Lifecycle state.
    pub state: McpServerState,
    /// Tools discovery produced (0 for disabled/failed/quarantined).
    pub tool_count: usize,
    /// Stable, content-free reason for a non-ready state.
    pub reason: Option<&'static str>,
}
