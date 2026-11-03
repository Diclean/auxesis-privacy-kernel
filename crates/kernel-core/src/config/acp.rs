//! ACP agent backends (`[acp]`) and their resource limits.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Default per-turn wall-clock cap for an ACP agent (maintainer decision: 10 min).
pub const DEFAULT_ACP_TURN_TIMEOUT_SECS: u64 = 600;

/// Default cap on ACP turns per task (maintainer decision: 20).
pub const DEFAULT_ACP_MAX_TURNS_PER_TASK: u32 = 20;

/// Default cap on ACP turn *attempts* started per rolling minute for one task:
/// a crash-looping agent must not burn the fixed per-turn reserve faster than
/// this. Failed attempts count exactly like successes.
pub const DEFAULT_ACP_MAX_TURNS_PER_MINUTE: u32 = 6;

/// Default output budget for one ACP turn (same 256 KiB as the shell tool).
pub const DEFAULT_ACP_MAX_OUTPUT_BYTES: usize = 256 * 1024;

/// Default bounded wait for one `session/request_permission` answer.
pub const DEFAULT_ACP_PERMISSION_TIMEOUT_SECS: u64 = 120;

/// Default conservative per-turn cost reserve, in whole cents. ACP backends
/// are flat-rate subscriptions (OpenCode Go) or not metered per token, so the
/// money cap can only bind through a fixed reserve per turn; usage_update is
/// recorded best-effort and never used to authorise spend.
pub const DEFAULT_ACP_TURN_COST_ESTIMATE_CENTS: u64 = 10;

/// Default `RLIMIT_CPU` for an ACP agent in seconds (`0` derives it from the
/// turn timeout plus a grace).
pub const DEFAULT_ACP_MAX_CPU_SECONDS: u64 = 0;

/// Default `RLIMIT_FSIZE` for an ACP agent: 1 GiB, same as the shell tool.
pub const DEFAULT_ACP_MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

/// Default `RLIMIT_NOFILE` for an ACP agent.
pub const DEFAULT_ACP_MAX_OPEN_FILES: u64 = 4096;

/// Default `RLIMIT_NPROC` headroom above the current user process count
/// (`0` disables the limit).
pub const DEFAULT_ACP_MAX_PROCESSES: u64 = 64;

/// Default best-effort `RLIMIT_AS`/`RLIMIT_DATA` for an ACP agent: 8 GiB.
pub const DEFAULT_ACP_MAX_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// ACP backends (`[acp]` in `config.toml`), **off by default**.
///
/// A0 wires the OpenCode Go path only: Claude Code stays API-key-only (never
/// enabled here), Codex/Gemini are opt-in in later phases. Every agent runs
/// in a per-agent scratch dir, never the repo or `~/.auxesis`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcpConfig {
    /// Master flag: ACP turns are refused while this is `false`.
    pub enabled: bool,
    /// Per-turn wall-clock cap in seconds (`0` falls back to the default).
    pub turn_timeout_secs: u64,
    /// Turns allowed per task before the backend refuses more.
    pub max_turns_per_task: u32,
    /// Turn attempts allowed per rolling minute per task (`0` disables the
    /// rate cap); failed/crashed attempts count exactly like successes.
    pub max_turns_per_minute: u32,
    /// Output budget for one turn, in bytes.
    pub max_output_bytes: usize,
    /// Bounded wait for one permission answer, in seconds.
    pub permission_timeout_secs: u64,
    /// Fixed cost reserve per turn, in whole cents.
    pub turn_cost_estimate_cents: u64,
    /// `RLIMIT_CPU` for the agent in seconds (`0` = turn timeout + grace).
    pub max_cpu_seconds: u64,
    /// `RLIMIT_FSIZE` for the agent, per file.
    pub max_file_bytes: u64,
    /// `RLIMIT_NOFILE` for the agent.
    pub max_open_files: u64,
    /// `RLIMIT_NPROC` headroom above the current user process count
    /// (`0` disables the limit).
    pub max_processes: u64,
    /// Best-effort `RLIMIT_AS`/`RLIMIT_DATA` for the agent (`0` disables).
    pub max_memory_bytes: u64,
    /// Agent definitions keyed by id (`[acp.agents.<id>]`).
    pub agents: BTreeMap<String, AcpAgentConfig>,
}

impl Default for AcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            turn_timeout_secs: DEFAULT_ACP_TURN_TIMEOUT_SECS,
            max_turns_per_task: DEFAULT_ACP_MAX_TURNS_PER_TASK,
            max_turns_per_minute: DEFAULT_ACP_MAX_TURNS_PER_MINUTE,
            max_output_bytes: DEFAULT_ACP_MAX_OUTPUT_BYTES,
            permission_timeout_secs: DEFAULT_ACP_PERMISSION_TIMEOUT_SECS,
            turn_cost_estimate_cents: DEFAULT_ACP_TURN_COST_ESTIMATE_CENTS,
            max_cpu_seconds: DEFAULT_ACP_MAX_CPU_SECONDS,
            max_file_bytes: DEFAULT_ACP_MAX_FILE_BYTES,
            max_open_files: DEFAULT_ACP_MAX_OPEN_FILES,
            max_processes: DEFAULT_ACP_MAX_PROCESSES,
            max_memory_bytes: DEFAULT_ACP_MAX_MEMORY_BYTES,
            agents: BTreeMap::new(),
        }
    }
}

impl AcpConfig {
    /// The effective wall-clock cap (zero falls back to the default).
    pub fn turn_timeout(&self) -> std::time::Duration {
        let secs = if self.turn_timeout_secs == 0 {
            DEFAULT_ACP_TURN_TIMEOUT_SECS
        } else {
            self.turn_timeout_secs
        };
        std::time::Duration::from_secs(secs)
    }

    /// The effective permission-answer wait (zero falls back to the default).
    pub fn permission_timeout(&self) -> std::time::Duration {
        let secs = if self.permission_timeout_secs == 0 {
            DEFAULT_ACP_PERMISSION_TIMEOUT_SECS
        } else {
            self.permission_timeout_secs
        };
        std::time::Duration::from_secs(secs)
    }
}

/// How one ACP agent authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AcpAuthMode {
    /// The CLI's own login, already present on this machine. We never read
    /// the credential store: the child gets read-only access when
    /// [`AcpAgentConfig::vendor_data_dir`] is set, and the owner's home is
    /// otherwise unreadable.
    #[default]
    #[serde(rename = "cli-login")]
    CliLogin,
    /// A metered API key. A0 does not resolve or pass API keys; the flag
    /// exists so the shape is stable and Claude Code can never default to a
    /// subscription login.
    #[serde(rename = "api-key")]
    ApiKey,
}

/// One `[acp.agents.<id>]` entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcpAgentConfig {
    /// Executable to run (found on the sandbox PATH).
    pub command: String,
    /// Arguments (for OpenCode: `["acp"]`).
    pub args: Vec<String>,
    /// Model label recorded for the run; the agent picks its own default in
    /// A0 (session model selection is a fast follow).
    pub model: String,
    /// Authentication mode (default `cli-login`).
    pub auth: AcpAuthMode,
    /// Optional `[[providers]]` id this agent serves. A turn whose selected
    /// provider has `kind = "acp"` uses the agent with this `provider_id`
    /// (or, when omitted, the provider's own id).
    pub provider_id: Option<String>,
    /// Read-only vendor data dir to expose to the child (`cli-login`), e.g.
    /// `~/.local/share/opencode`. The child may read its own login from
    /// there; we never copy or read the token ourselves, and nothing else of
    /// the real home becomes readable.
    pub vendor_data_dir: Option<String>,
    /// Extra environment variable **names** to pass through from the daemon
    /// (values are copied). `AUX_KEY_*`, `HOME` and `TMPDIR` are refused: the
    /// child must never see the daemon's secrets or paths.
    pub env_passthrough: Vec<String>,
}

impl Default for AcpAgentConfig {
    fn default() -> Self {
        Self {
            command: String::new(),
            args: Vec::new(),
            model: String::new(),
            auth: AcpAuthMode::CliLogin,
            provider_id: None,
            vendor_data_dir: None,
            env_passthrough: Vec::new(),
        }
    }
}
