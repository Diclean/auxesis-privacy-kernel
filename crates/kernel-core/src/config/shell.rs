//! Shell tool sandbox settings (`[shell]`).

use serde::{Deserialize, Serialize};

/// Shell tool sandbox settings (`[shell]` in `config.toml`).
///
/// Defaults are the safe ones: sandboxed, no network, and fail closed when
/// the platform cannot sandbox.
///
/// - `sandbox = false` only takes effect together with
///   `allow_unsandboxed = true`; on its own it makes every `shell` call
///   refuse to run. Both the disable and the unsandboxed run are logged
///   loudly.
/// - `network = true` means **all sockets** inside the sandbox for v1: any
///   host and any port, loopback included. There is no narrower
///   host/port allowlist.
/// - `allow_unsandboxed = true` is the explicit escape hatch for systems
///   without `sandbox-exec`; it is logged loudly when used.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShellConfig {
    /// Run shell commands under `sandbox-exec` (macOS Seatbelt). `false` only
    /// takes effect together with [`ShellConfig::allow_unsandboxed`].
    pub sandbox: bool,
    /// Allow network access inside the sandbox (default false: all sockets
    /// denied, loopback included). `true` is **all sockets** for v1.
    pub network: bool,
    /// Run unsandboxed when the sandbox is unavailable, and when `sandbox` is
    /// explicitly disabled.
    pub allow_unsandboxed: bool,
    /// Wall-clock cap on one command, in seconds (default
    /// [`DEFAULT_SHELL_TIMEOUT_SECS`]). `0` falls back to the default.
    pub timeout_secs: u64,
}

/// Default wall-clock cap on one shell command (SHELL-JUDGE, maintainer OK).
pub const DEFAULT_SHELL_TIMEOUT_SECS: u64 = 30;

/// The longest `[shell] timeout_secs` a config may set: one hour.
pub const MAX_SHELL_TIMEOUT_SECS: u64 = 3600;

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            sandbox: true,
            network: false,
            allow_unsandboxed: false,
            timeout_secs: DEFAULT_SHELL_TIMEOUT_SECS,
        }
    }
}

impl ShellConfig {
    /// The wall-clock cap in force: `timeout_secs`, or the default for `0`,
    /// never above [`MAX_SHELL_TIMEOUT_SECS`].
    pub fn timeout(&self) -> std::time::Duration {
        let secs = match self.timeout_secs {
            0 => DEFAULT_SHELL_TIMEOUT_SECS,
            secs => secs.min(MAX_SHELL_TIMEOUT_SECS),
        };
        std::time::Duration::from_secs(secs)
    }
}
