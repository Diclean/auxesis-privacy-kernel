//! KMCP-HARDEN-b: the bytes that run must be the bytes that were confirmed.
//!
//! The runtime hashes the `stdio` program when the transport is built
//! (`build_stdio_transport` → `stdio_is_confirmed_with`), but the child is
//! spawned lazily on the first round trip (`StdioTransport::ensure_started`).
//! A file replaced at the canonical path after confirmation and before that
//! first spawn therefore runs unconfirmed bytes on main.
//!
//! Offline and deterministic — no sleeps, no races: confirm the launch,
//! build the transport, replace the file, then trigger the first round trip.
//! The `test-util` unsandboxed transport (enabled only by this crate's own
//! `[dev-dependencies]`) is used so the spawned child is exactly the file at
//! the pinned path on any host.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use serde_json::json;

use kernel_mcp::{
    JsonRpcRequest, McpDataClass, McpServerConfig, McpTransport, StdioCommand, StdioLimits,
    StdioTransport, Transport,
};

#[tokio::test]
#[ignore = "KMCP-HARDEN-b: fails until the fix lands"]
async fn kmcp_harden_b_replaced_program_before_first_spawn_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("server");
    let marker = dir.path().join("SWAPPED-PROGRAM-RAN");
    std::fs::write(&bin, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let program = bin.to_string_lossy().into_owned();

    // The confirmation moment: the digest hashes the program file NOW.
    let mut server = McpServerConfig {
        id: "s".into(),
        catalog_id: None,
        data_class: McpDataClass::Sensitive,
        stdio_confirmed: true,
        stdio_confirmation: None,
        approval: None,
        network: false,
        transport: McpTransport::Stdio,
        url: None,
        command: Some(program.clone()),
        args: Vec::new(),
        env: Vec::new(),
        enabled: true,
        agents: Default::default(),
    };
    let secret = b"kmcp-harden-b-key";
    server.stdio_confirmation = server.confirmation_binding(secret);
    assert!(
        server.stdio_is_confirmed_with(secret),
        "the launch is confirmed against the current file"
    );

    // Build the transport for the confirmed launch — the same `StdioTransport`
    // the runtime's spawn path builds for a confirmed server.
    let command = StdioCommand::new(&program).expect("absolute pinned path");
    let transport = StdioTransport::new_for_tests(command, StdioLimits::default())
        .expect("the transport builds for a confirmed launch");

    // Replace the file at the canonical path AFTER confirmation, BEFORE the
    // first spawn. The replacement records that it ran.
    std::fs::write(
        &bin,
        format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.display()),
    )
    .unwrap();
    // Sanity: the digest itself catches the swap when it is re-checked...
    assert!(
        !server.stdio_is_confirmed_with(secret),
        "re-checking the digest now does catch the swap"
    );

    // ...but the first round trip spawns lazily, and on main nothing re-checks
    // the file at spawn time.
    let result = transport
        .round_trip(
            JsonRpcRequest::new(0, "initialize", json!({})),
            Duration::from_secs(2),
        )
        .await;
    assert!(
        result.is_err(),
        "a program replaced after confirmation and before the first spawn must be \
         refused, not executed: got {result:?}"
    );
    assert!(
        !marker.exists(),
        "the replaced program ran (marker file was created): the bytes that ran were \
         not the bytes that were confirmed"
    );
    let _ = transport.shutdown().await;
}
