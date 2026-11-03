//! Tests for start options and runtime startup.

use std::collections::BTreeMap;

use super::super::*;
use super::support::stdio_server;

#[test]
fn start_options_expose_no_sandbox_opt_out() {
    // Compile-time absence. `McpStartOptions` is a plain public struct (not
    // `#[non_exhaustive]`) and this literal names every field, so adding a
    // `sandbox_stdio`-style switch back breaks the build here. The struct's
    // `compile_fail` doctest is the same tripwire from a caller's view.
    let options = McpStartOptions {
        network_guard: true,
        confirmation_secret: None,
    };
    assert!(options.network_guard);
    assert!(options.confirmation_secret.is_none());
}

#[test]
fn default_start_options_fail_closed() {
    let options = McpStartOptions::default();
    assert!(options.network_guard, "the SSRF guard is on by default");
    let secret = options
        .confirmation_secret
        .as_deref()
        .expect("a key is present so an unconfirmed stdio launch is refused");
    let mut server = stdio_server("s", "/usr/local/bin/tool");
    server.stdio_confirmed = true;
    assert!(
        !server.stdio_is_confirmed_with(secret),
        "an empty default key can never confirm a server"
    );
}

#[tokio::test]
async fn runtime_start_refuses_an_unconfirmed_stdio_server_by_default() {
    let runtime = McpRuntime::start(
        McpConfig::from_servers(vec![stdio_server("s", "/usr/local/bin/tool")]),
        &BTreeMap::new(),
    )
    .await;
    assert_eq!(runtime.statuses().len(), 1);
    assert_eq!(
        runtime.statuses()[0].state,
        McpServerState::Failed,
        "the default options must refuse an unconfirmed stdio spawn"
    );
    assert_eq!(runtime.statuses()[0].reason, Some("command_refused"));
    assert_eq!(runtime.tool_count(), 0);
}
