//! The SSE path: line terminators, ids, notifications, the BOM and the line
//! bomb.

use axum::http::HeaderMap;

use kernel_mcp::{Limits, McpError, ServerInfo};

use crate::helpers::{serial, spawn, transport};

/// P2: the SSE path must require the response id to match too.
#[tokio::test]
async fn sse_response_id_must_match_the_request() {
    let _guard = serial().await;
    for path in ["/mcp/sse-no-id", "/mcp/sse-wrong-id"] {
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

/// P3: the SSE parser accepts LF, CRLF and bare CR terminators.
#[tokio::test]
async fn sse_accepts_lf_crlf_and_cr_terminators() {
    let _guard = serial().await;
    for path in ["/mcp/sse-lf", "/mcp/sse-crlf", "/mcp/sse-cr"] {
        let mock = spawn().await;
        let transport = transport(&mock, path, HeaderMap::new(), Limits::default());
        let client = kernel_mcp::client(transport, ServerInfo::default());
        let page = client.list_tools(None).await.expect(path);
        assert_eq!(page.tools.len(), 1, "{path}");
        assert_eq!(page.tools[0].name, "EOL_TOOL", "{path}");
    }
}

#[tokio::test]
async fn sse_notification_is_ignored_and_response_returned() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/sse", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport.clone(), ServerInfo::default());

    let page = client.list_tools(None).await.expect("list tools");
    assert_eq!(page.tools.len(), 1);
    assert_eq!(page.tools[0].name, "SSE_TOOL");
    assert_eq!(transport.last_event_id().as_deref(), Some("evt-42"));
}

#[tokio::test]
async fn sse_line_bomb_is_bounded() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/sse-bomb", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    // Warm the connection first so this checks the streaming bound after normal
    // client/hyper setup has completed.
    client.initialize().await.expect("warm initialize");

    let err = client.list_tools(None).await.unwrap_err();

    let (limit, seen) = match err {
        McpError::FrameTooLarge { limit, seen } => (limit, seen),
        other => panic!("expected FrameTooLarge, got {other:?}"),
    };
    assert_eq!(limit, 1024 * 1024);
    // The parser stops within one read chunk of the line bound, never at 4 MiB.
    assert!(
        seen < limit + 1024 * 1024,
        "buffered {seen} bytes past a {limit} byte line"
    );
}

/// NP-6: a leading UTF-8 BOM does not hide the first SSE `data:` line.
#[tokio::test]
async fn sse_leading_bom_is_stripped() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/sse-bom", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let page = client.list_tools(None).await.expect("BOM-prefixed stream");
    assert_eq!(page.tools.len(), 1);
    assert_eq!(page.tools[0].name, "BOM_TOOL");
}

/// NP-9: the SSE `id:` is sanitised and capped before it is retained.
#[tokio::test]
async fn last_event_id_is_sanitised() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/sse-evil-id",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport.clone(), ServerInfo::default());

    let page = client.list_tools(None).await.expect("stream");
    assert_eq!(page.tools.len(), 1);
    let id = transport.last_event_id().expect("event id retained");
    assert!(id.len() <= 256, "event id was not capped: {}", id.len());
    assert!(
        !id.chars().any(char::is_control),
        "event id has control characters: {id:?}"
    );
}
