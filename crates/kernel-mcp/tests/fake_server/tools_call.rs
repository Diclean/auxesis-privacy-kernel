//! Calling a tool over HTTP: the result envelope, the typed errors and the
//! no-retry rule.

use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::http::HeaderMap;
use serde_json::json;

use kernel_mcp::{Limits, McpError, ServerInfo};

use crate::helpers::{safe_args, serial, spawn, transport};

#[tokio::test]
async fn tools_call_is_never_retried() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());
    client.initialize().await.expect("initialize");

    let outcome = client
        .call_tool(
            "ELEVENLABS_TEXT_TO_SPEECH",
            &safe_args(&json!({})),
            Duration::from_secs(5),
        )
        .await
        .expect("call");
    assert!(!outcome.is_error);
    assert_eq!(
        outcome.text().marked(),
        format!("{}\nok", kernel_mcp::UNTRUSTED_MCP_TAG)
    );
    assert!(outcome.bytes > 0);
    assert_eq!(mock.state.call_hits.load(Ordering::SeqCst), 1);

    let missing = client
        .call_tool("MISSING", &safe_args(&json!({})), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(missing, McpError::ToolNotFound("MISSING".into()));
    assert_eq!(mock.state.call_hits.load(Ordering::SeqCst), 2);

    // P3: `-32602` is shared with a bad argument set and must not map blindly.
    let bad_args = client
        .call_tool("BADARGS", &safe_args(&json!({})), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        matches!(bad_args, McpError::Protocol { code: -32602, .. }),
        "got {bad_args:?}"
    );
    assert_eq!(mock.state.call_hits.load(Ordering::SeqCst), 3);

    let failing = client
        .call_tool("FAILS", &safe_args(&json!({})), Duration::from_secs(5))
        .await
        .expect("call");
    assert!(failing.is_error);
    assert_eq!(mock.state.call_hits.load(Ordering::SeqCst), 4);
}
