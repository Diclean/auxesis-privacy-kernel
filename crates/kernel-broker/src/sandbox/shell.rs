//! The shell tool's sandbox settings: the three `[shell]` switches and the
//! fixed helper path they run through.

use super::limits::SANDBOX_EXEC;
use std::path::{Path, PathBuf};

/// Sandbox settings for the shell tool, mirroring the `[shell]` config section.
///
/// The helper path is private and always [`SANDBOX_EXEC`] outside tests: no
/// caller can point the shell at a wrapper that skips the Seatbelt profile.
///
/// ```compile_fail,E0451
/// use kernel_broker::sandbox::ShellSandbox;
/// // The helper is private: a struct literal from outside the crate cannot set it.
/// let _ = ShellSandbox {
///     enabled: true,
///     network: false,
///     allow_unsandboxed: false,
///     sandbox_exec: "/tmp/wrapper".into(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellSandbox {
    /// Run commands under `sandbox-exec` (default true). `false` only takes
    /// effect together with [`ShellSandbox::allow_unsandboxed`]; on its own it
    /// makes every call refuse to run.
    pub enabled: bool,
    /// Allow network access inside the sandbox (default false: all sockets are
    /// denied, loopback included). `true` is **all sockets** for v1 — any host
    /// and port; there is no narrower allowlist.
    pub network: bool,
    /// Run unsandboxed when the sandbox is unavailable *and* when
    /// `enabled` is false (default false).
    pub allow_unsandboxed: bool,
    /// Path of the sandbox helper. Always [`SANDBOX_EXEC`] outside tests (see
    /// [`ShellSandbox::with_test_sandbox_exec`]).
    pub(super) sandbox_exec: PathBuf,
}

impl Default for ShellSandbox {
    fn default() -> Self {
        Self::new(true, false, false)
    }
}

impl ShellSandbox {
    /// The profile for the three `[shell]` config switches, always run through
    /// the fixed [`SANDBOX_EXEC`] helper.
    pub fn new(enabled: bool, network: bool, allow_unsandboxed: bool) -> Self {
        Self {
            enabled,
            network,
            allow_unsandboxed,
            sandbox_exec: PathBuf::from(SANDBOX_EXEC),
        }
    }

    /// Test seam: run this profile through another helper path. A missing path
    /// exercises the fail-closed branch. Compiled out of production builds, so
    /// the helper there is always [`SANDBOX_EXEC`].
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn with_test_sandbox_exec(mut self, sandbox_exec: impl Into<PathBuf>) -> Self {
        self.sandbox_exec = sandbox_exec.into();
        self
    }

    /// The helper binary this profile runs commands through.
    pub fn sandbox_exec(&self) -> &Path {
        &self.sandbox_exec
    }

    /// True when this platform and this binary can actually sandbox.
    pub fn available(&self) -> bool {
        cfg!(target_os = "macos") && self.sandbox_exec.is_file()
    }

    /// True when a command launched under this profile will run **without**
    /// the sandbox: the explicit `enabled = false` opt-out, or an unavailable
    /// sandbox helper with `allow_unsandboxed` set. Mirrors the decision in
    /// [`launch`](super::launch) exactly, so the broker can refuse persistent allows for a
    /// call that will escape the sandbox. `enabled = false` without the opt-in
    /// (or an unavailable helper without it) refuses to run and is therefore
    /// *not* unsandboxed.
    pub fn will_run_unsandboxed(&self) -> bool {
        self.allow_unsandboxed && (!self.enabled || !self.available())
    }
}
