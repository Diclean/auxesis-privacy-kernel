//! The JSON-RPC protocol surface: id matching, notifications, the negotiated
//! revision and the server-info caps.

use std::sync::atomic::Ordering;

use axum::http::HeaderMap;

use kernel_mcp::{Limits, McpError, ServerInfo};

use crate::helpers::{serial, spawn, transport};

/// P3: the negotiated version rides every request after `initialize`.
#[tokio::test]
async fn protocol_version_header_is_sent_after_initialize() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    client.initialize().await.expect("initialize");
    client.list_tools(None).await.expect("list tools");
    let list_hits = mock.state.list_hits.load(Ordering::SeqCst);
    assert_eq!(list_hits, 3);
    assert_eq!(
        mock.state.list_with_protocol_header.load(Ordering::SeqCst),
        list_hits,
        "every post-initialize request must carry MCP-Protocol-Version"
    );
}

/// P3: a JSON-RPC notification must not carry an `id` member.
#[tokio::test]
async fn notifications_are_sent_without_an_id_member() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    client.initialize().await.expect("initialize");
    assert_eq!(mock.state.notification_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        mock.state.notification_with_id.load(Ordering::SeqCst),
        0,
        "the initialized notification carried an id"
    );
}

/// P2: the plain-JSON path must require the response id to match.
#[tokio::test]
async fn json_response_id_must_match_the_request() {
    let _guard = serial().await;
    for path in ["/mcp/no-id", "/mcp/wrong-id"] {
        let mock = spawn().await;
        let transport = transport(&mock, path, HeaderMap::new(), Limits::default());
        let client = kernel_mcp::client(transport, ServerInfo::default());
        let err = client.list_tools(None).await.unwrap_err();
        match err {
            McpError::Protocol { message, .. } => {
                assert!(message.as_str().contains("id"), "{path}: {message}")
            }
            other => panic!("{path}: expected Protocol, got {other:?}"),
        }
    }
}

/// NP-4: server info strings are sanitised (no control characters/ANSI) and
/// capped.
#[tokio::test]
async fn server_info_strings_are_sanitised_and_capped() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/evil-info", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let info = client.initialize().await.expect("initialize");
    assert!(
        info.name.len() <= 256,
        "name not capped: {}",
        info.name.len()
    );
    assert!(
        !info.name.chars().any(char::is_control),
        "name has control characters: {:?}",
        info.name
    );
    assert!(info.version.len() <= 256, "version not capped");
    assert!(!info.version.chars().any(char::is_control));
    let instructions = info.instructions.expect("instructions present");
    assert!(
        instructions.len() <= 4 * 1024,
        "instructions not capped: {}",
        instructions.len()
    );
    assert!(!instructions.chars().any(char::is_control));
}

/// NP-5: a non-date-shaped negotiated revision is a typed protocol error, while
/// a date-shaped one this build predates is accepted.
#[tokio::test]
async fn negotiated_protocol_version_is_validated() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport1 = transport(
        &mock,
        "/mcp/bad-version",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport1, ServerInfo::default());
    let err = client.initialize().await.unwrap_err();
    match &err {
        McpError::Protocol { message, .. } => assert!(
            message.as_str().contains("protocol version"),
            "got {message}"
        ),
        other => panic!("expected Protocol, got {other:?}"),
    }

    let mock2 = spawn().await;
    let transport2 = transport(
        &mock2,
        "/mcp/old-version",
        HeaderMap::new(),
        Limits::default(),
    );
    let client2 = kernel_mcp::client(transport2, ServerInfo::default());
    let info = client2.initialize().await.expect("old but date-shaped");
    assert_eq!(info.protocol_version, "2024-11-05");
}

/// NP-8: `ServerInfo::max_tools` outside `1..=2000` is a typed config error.
#[tokio::test]
async fn server_info_max_tools_is_validated() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());

    for bad in [0usize, 2001] {
        let client = kernel_mcp::client(
            transport.clone(),
            ServerInfo {
                max_tools: bad,
                ..ServerInfo::default()
            },
        );
        let err = client.list_tools(None).await.unwrap_err();
        assert!(
            matches!(
                err,
                McpError::InvalidLimit {
                    field: "max_tools",
                    ..
                }
            ),
            "max_tools={bad}: got {err:?}"
        );
    }

    let client = kernel_mcp::client(
        transport,
        ServerInfo {
            max_tools: 2000,
            ..ServerInfo::default()
        },
    );
    assert!(
        client.list_tools(None).await.is_ok(),
        "2000 must be accepted"
    );
}
