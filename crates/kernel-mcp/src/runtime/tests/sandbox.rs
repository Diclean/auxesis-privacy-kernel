//! Tests for the sandboxed `stdio` spawn path.

use std::collections::BTreeMap;

#[cfg(not(target_os = "macos"))]
use crate::stdio::{StdioCommand, StdioLimits};

#[cfg(not(target_os = "macos"))]
use super::super::spawn::unsandboxed_stdio_transport;
use super::super::spawn::{build_stdio_transport, canonical_stdio_program, stdio_sandbox_at};
#[cfg(not(target_os = "macos"))]
use super::super::McpStartError;
use super::support::stdio_server;

#[test]
fn sandbox_unavailable_refuses_a_stdio_spawn_on_macos() {
    let server = stdio_server("s", "/usr/local/bin/tool");
    let missing = std::path::Path::new("/nonexistent/sandbox-exec");
    let outcome = stdio_sandbox_at(&server, missing);
    if cfg!(target_os = "macos") {
        let err = outcome.expect_err("a missing sandbox-exec must refuse, never degrade");
        assert_eq!(err.kind(), "sandbox_unavailable");
    } else {
        assert!(outcome.is_ok(), "non-macOS keeps the current behaviour");
    }
}

/// On a host with no OS sandbox and no `test-util`, the launch path must
/// refuse, never spawn a bare child.
///
/// [`unsandboxed_stdio_transport`] takes the decision as a parameter, so
/// this drives the value a production build computes (`false`) directly. It
/// therefore holds in this test build too, even though the self
/// dev-dependency has `test-util` on. `true` is the documented escape hatch
/// and is exercised by the spawn-path test above.
#[cfg(not(target_os = "macos"))]
#[test]
fn non_macos_stdio_without_test_util_is_refused() {
    let command = StdioCommand::new("/usr/bin/true").expect("absolute path");
    let err = unsandboxed_stdio_transport(command, StdioLimits::default(), false)
        .expect_err("a non-macOS host without `test-util` must refuse, never spawn");
    assert_eq!(err, McpStartError::SandboxUnavailable);
    assert_eq!(err.kind(), "sandbox_unavailable");
}

#[test]
fn spawn_time_confirmation_rejects_a_swapped_binary() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("server");
    std::fs::write(&bin, b"one").unwrap();
    let mut server = stdio_server("s", &bin.to_string_lossy());
    let secret = b"daemon-key";
    server.stdio_confirmed = true;
    server.stdio_confirmation = server.confirmation_binding(secret);
    assert!(server.stdio_is_confirmed_with(secret));
    std::fs::write(&bin, b"two").unwrap();
    assert!(
        !server.stdio_is_confirmed_with(secret),
        "a binary swapped after confirmation must fail the spawn-time digest"
    );
}

#[test]
fn stdio_spawn_uses_the_canonical_path_that_was_hashed() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real-tool");
    std::fs::write(&real, b"binary").unwrap();
    let link = dir.path().join("link-tool");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let canonical = canonical_stdio_program(&link.to_string_lossy());
    assert_eq!(
        canonical,
        std::fs::canonicalize(&real).unwrap().to_string_lossy(),
        "the spawn path must be the resolved target, not the symlink"
    );

    // The confirmation binds the canonical path: confirming the link and
    // then retargeting it invalidates the confirmation (item 8).
    let secret = b"daemon-key";
    let mut server = stdio_server("s", &link.to_string_lossy());
    server.stdio_confirmed = true;
    server.stdio_confirmation = server.confirmation_binding(secret);
    assert!(server.stdio_is_confirmed_with(secret));
    let other = dir.path().join("other-tool");
    std::fs::write(&other, b"binary").unwrap();
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&other, &link).unwrap();
    assert!(
        !server.stdio_is_confirmed_with(secret),
        "retargeting the symlink must invalidate the confirmation"
    );
}

/// The one spawn path must attach the Seatbelt profile on macOS.
///
/// [`build_stdio_transport`] is exactly what [`build_client`](super::super::build_client)
/// calls for a
/// `stdio` server, so this asserts against the code that spawns, not a
/// stand-in. It takes no sandbox argument: on macOS the profile is always
/// attached, and no key means the spawn is refused before the transport
/// exists. On a host with no Seatbelt this test build has `test-util` on
/// (the self dev-dependency), so the private `cfg(not(target_os = "macos"))`
/// branch leaves `sandbox` empty — a platform property the public API
/// cannot influence. A production build on that host refuses instead
/// (`non_macos_stdio_without_test_util_is_refused`).
#[test]
fn stdio_spawn_path_has_no_public_sandbox_opt_out() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("server");
    std::fs::write(&bin, b"fake-server").unwrap();
    let secret = b"daemon-key";
    let mut server = stdio_server("s", &bin.to_string_lossy());
    server.stdio_confirmed = true;
    server.stdio_confirmation = server.confirmation_binding(secret);

    let transport = build_stdio_transport(&server, &BTreeMap::new(), Some(secret))
        .expect("a confirmed server builds its transport");
    if cfg!(target_os = "macos") {
        assert!(
            transport.has_sandbox(),
            "macOS must always attach the profile: the spawn path has no \
                 sandbox opt-out"
        );
    } else {
        assert!(
            !transport.has_sandbox(),
            "this host has no Seatbelt; the platform `cfg` branch is what \
                 leaves the transport bare, never a caller flag"
        );
    }

    // Defence in depth: no confirmation key still refuses the spawn, so
    // the missing sandbox can never be reached through a keyless caller.
    assert!(
        build_stdio_transport(&server, &BTreeMap::new(), None).is_err(),
        "a keyless caller must never reach the spawn path"
    );
}
