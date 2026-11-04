//! The `stdio` spawn path: confirmation, canonical path and Seatbelt sandbox.

use std::collections::BTreeMap;

use crate::config::{binary_sha256, McpServerConfig};
use crate::stdio::{StdioCommand, StdioLimits, StdioTransport};

use super::status::McpStartError;

/// Build the pinned, confirmed `stdio` transport for one server.
///
/// This is the **single** spawn path: [`build_client`](super::build_client) calls it and the
/// acceptance test calls it, so "the sandbox is attached" is proven against the
/// very code that spawns. On macOS the Seatbelt profile is a required argument
/// to [`StdioTransport::new`] — there is no parameter, flag or option that skips
/// it, and the crate-private unsandboxed constructor is unreachable outside
/// kernel-mcp.
///
/// A missing `sandbox-exec` on macOS is [`McpStartError::SandboxUnavailable`]
/// (a quarantine), never a silent unsandboxed spawn. On a platform without an
/// OS sandbox the private [`stdio_sandbox`] returns `None` (`cfg` path) and the
/// launch path **refuses** with [`McpStartError::SandboxUnavailable`]: a caller
/// of the public API on Linux gets a quarantine, not an unsandboxed child. The
/// only escape hatch is a build with the `test-util` feature, which only test
/// `[dev-dependencies]` enable ([`unsandboxed_stdio_transport`]).
pub(super) fn build_stdio_transport(
    server: &McpServerConfig,
    secrets: &BTreeMap<String, String>,
    confirmation_secret: Option<&[u8]>,
) -> Result<StdioTransport, McpStartError> {
    let command = server
        .command
        .as_deref()
        .ok_or(McpStartError::Command("missing command"))?;
    // Item 8: canonicalise once and use that exact path for the policy
    // re-check, the confirmation digest **and** the spawn, so a symlink
    // cannot be swapped between the check and `execve`.
    let canonical = canonical_stdio_program(command);
    let mut launch = server.clone();
    launch.command = Some(canonical.clone());
    // Re-run the policy at spawn time, not only at parse time: a
    // symlink retargeted after load is caught here.
    aux_crate_stdio_recheck(&launch)?;
    // Item 4: re-verify at spawn time. The digest includes the binary's
    // SHA-256, so a binary swapped after confirmation is refused here.
    // Item 6 (defence in depth): a missing key is not a bypass — with
    // no key nothing can be confirmed, so the spawn is refused.
    let sha = binary_sha256(std::path::Path::new(&canonical));
    match confirmation_secret {
        Some(secret)
            if launch.stdio_confirmed
                && launch.stdio_confirmation.is_some()
                && launch.confirmation_binding_for_sha(secret, &sha)
                    == launch.stdio_confirmation => {}
        _ => return Err(McpStartError::Command("confirmation_missing")),
    }
    let mut pinned = StdioCommand::new(canonical.as_str())
        .map_err(|_| McpStartError::Command("invalid absolute command"))?
        .verified_sha(sha)
        .args(server.args.iter().cloned());
    for name in &server.env {
        let Some(value) = secrets.get(name) else {
            return Err(McpStartError::MissingSecret { name: name.clone() });
        };
        pinned = pinned
            .env_declared(name, value.clone())
            .map_err(|_| McpStartError::Command("declared env key refused"))?;
    }
    let limits = StdioLimits::default();
    // Item 8: the Seatbelt profile is a *required* constructor argument, never
    // an option attached afterwards. On macOS `stdio_sandbox` yields the
    // mandatory wrapper or refuses the spawn. A host with no OS sandbox at all
    // is refused too: only a `test-util` build (the test suites'
    // `[dev-dependencies]`) may build the raw crate-private transport.
    match stdio_sandbox(server)? {
        Some(sandbox) => StdioTransport::new(pinned, limits, sandbox)
            .map_err(|_| McpStartError::Command("invalid stdio limits")),
        None => unsandboxed_stdio_transport(pinned, limits, test_util_enabled()),
    }
}

/// Whether this build may run a `stdio` server with no OS sandbox attached.
///
/// `true` only with the `test-util` feature, which nothing but a
/// `[dev-dependencies]` entry enables (kernel-mcp's own and the daemon's integration
/// tests). Every production build (the app's daemon and CLI) answers `false`, so a host
/// without an OS sandbox refuses the spawn instead of running a bare child.
const fn test_util_enabled() -> bool {
    cfg!(feature = "test-util")
}

/// Build the transport for a host with no OS sandbox, or refuse.
///
/// `test_util` is [`test_util_enabled`] at the launch site; it is a parameter so
/// a unit test can drive the production answer (`false`) directly, without
/// needing a separate build that omits the feature. A refusal is
/// [`McpStartError::SandboxUnavailable`]: a server the platform cannot sandbox
/// is quarantined, never spawned raw.
pub(super) fn unsandboxed_stdio_transport(
    pinned: StdioCommand,
    limits: StdioLimits,
    test_util: bool,
) -> Result<StdioTransport, McpStartError> {
    if !test_util {
        return Err(McpStartError::SandboxUnavailable);
    }
    test_only_stdio_transport(pinned, limits)
}

/// The `test-util`-gated escape hatch to the crate-private unsandboxed
/// constructor. A production build has no such path.
#[cfg(feature = "test-util")]
fn test_only_stdio_transport(
    pinned: StdioCommand,
    limits: StdioLimits,
) -> Result<StdioTransport, McpStartError> {
    StdioTransport::new_for_tests(pinned, limits)
        .map_err(|_| McpStartError::Command("invalid stdio limits"))
}

/// Without `test-util` there is no escape hatch. The launch site never asks for
/// one in this build: `test_util` comes from the very feature this branch is
/// compiled out of.
#[cfg(not(feature = "test-util"))]
fn test_only_stdio_transport(
    _pinned: StdioCommand,
    _limits: StdioLimits,
) -> Result<StdioTransport, McpStartError> {
    Err(McpStartError::SandboxUnavailable)
}

/// The canonical (symlink-resolved) program path when it exists, else the path
/// as written.
///
/// The policy re-check, the confirmation digest and the spawn all use this one
/// value, so the file that was checked is the file that is executed (item 8).
pub(super) fn canonical_stdio_program(command: &str) -> String {
    std::fs::canonicalize(command)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| command.to_owned())
}

/// Re-run the stdio hard-refusal policy against the current filesystem.
fn aux_crate_stdio_recheck(server: &McpServerConfig) -> Result<(), McpStartError> {
    let Some(command) = server.command.as_deref() else {
        return Err(McpStartError::Command("missing command"));
    };
    crate::config::evaluate_stdio_policy(&server.id, command, &server.args, server.network)
        .map(|_| ())
        .map_err(|_| McpStartError::Command("policy refused at spawn time"))
}

/// Build the shared macOS Seatbelt wrapper, or `None` where unsupported.
///
/// The launch path calls this for **every** `stdio` server, with no option to
/// skip it. On macOS the wrapper is mandatory: if `sandbox-exec` is missing the
/// spawn is refused (`sandbox_unavailable`), never silently unsandboxed
/// (item 8). On a host with no Seatbelt at all the `cfg(not(target_os =
/// "macos"))` branch returns `None`; the launch path then refuses with
/// `sandbox_unavailable` ([`unsandboxed_stdio_transport`]), except in a
/// `test-util` build. That is a platform property, not a caller switch.
fn stdio_sandbox(
    server: &McpServerConfig,
) -> Result<Option<kernel_broker::sandbox::StdioSandbox>, McpStartError> {
    stdio_sandbox_at(
        server,
        std::path::Path::new(kernel_broker::sandbox::SANDBOX_EXEC),
    )
}

/// Testable core of [`stdio_sandbox`]: `sandbox_exec` is passed in so a test
/// can point it at a missing binary and exercise the refusal.
pub(super) fn stdio_sandbox_at(
    server: &McpServerConfig,
    sandbox_exec: &std::path::Path,
) -> Result<Option<kernel_broker::sandbox::StdioSandbox>, McpStartError> {
    let Some(command) = server.command.as_deref() else {
        return Ok(None);
    };
    #[cfg(target_os = "macos")]
    {
        if !sandbox_exec.is_file() {
            return Err(McpStartError::SandboxUnavailable);
        }
        kernel_broker::sandbox::StdioSandbox::new(std::path::Path::new(command), server.network)
            .map(Some)
            .map_err(|_| McpStartError::SandboxUnavailable)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (command, sandbox_exec);
        Ok(None)
    }
}
