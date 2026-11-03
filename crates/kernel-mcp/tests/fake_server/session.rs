//! How the client negotiates `Mcp-Session-Id` and when it remembers one.

use std::sync::atomic::Ordering;

use axum::http::HeaderMap;

use kernel_mcp::{Limits, McpError, ServerInfo};

use crate::helpers::{serial, spawn, transport};

#[tokio::test]
async fn initialize_negotiates_and_tolerates_absent_session() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport.clone(), ServerInfo::default());

    let info = client.initialize().await.expect("initialize");
    assert_eq!(info.name, "mock-server");
    assert_eq!(info.version, "0.1.0");
    assert_eq!(info.protocol_version, "2025-11-25");
    assert_eq!(info.max_tools, 500);
    assert!(transport.session_id().is_none());
    assert_eq!(mock.state.init_hits.load(Ordering::SeqCst), 1);

    // Stateless follow-up: no session header, and the server is fine with it.
    let page = client.list_tools(None).await.expect("list tools");
    assert_eq!(page.tools.len(), 5);
    assert!(page.next_cursor.is_none());
    assert_eq!(page.dropped, 0);
    assert_eq!(mock.state.list_with_session.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn session_id_is_reused_when_present() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/session", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport.clone(), ServerInfo::default());

    client.initialize().await.expect("initialize");
    assert_eq!(transport.session_id().as_deref(), Some("sess_mock_1"));

    client.list_tools(None).await.expect("list tools");
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 3);
    assert_eq!(mock.state.list_with_session.load(Ordering::SeqCst), 3);
}

/// P3: a session id is remembered only from a 2xx response and is capped.
#[tokio::test]
async fn session_id_is_captured_only_on_2xx_and_is_capped() {
    let _guard = serial().await;

    let mock = spawn().await;
    let transport_err = transport(
        &mock,
        "/mcp/session-error",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport_err.clone(), ServerInfo::default());
    let err = client.initialize().await.unwrap_err();
    assert!(matches!(err, McpError::Http { status: 500 }), "got {err:?}");
    assert!(
        transport_err.session_id().is_none(),
        "a session id on a 500 was remembered"
    );

    let mock = spawn().await;
    let transport_long = transport(
        &mock,
        "/mcp/session-long",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport_long.clone(), ServerInfo::default());
    client.initialize().await.expect("initialize");
    let session = transport_long.session_id().expect("session id");
    assert_eq!(session.len(), 256, "session id was not capped");
}
