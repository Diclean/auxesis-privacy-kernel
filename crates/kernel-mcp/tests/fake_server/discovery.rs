//! Discovery: `tools/list` pagination, its cursor guards and its bounds.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;

use kernel_mcp::{Limits, McpError, ServerInfo};

use crate::helpers::{serial, spawn, transport};

#[tokio::test]
async fn tools_list_paginates_and_stops_at_max_tools() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let info = ServerInfo {
        max_tools: 3,
        ..ServerInfo::default()
    };
    let client = kernel_mcp::client(transport, info);

    let page = client.list_tools(None).await.expect("list tools");
    let names: Vec<&str> = page.tools.iter().map(|tool| tool.name.as_str()).collect();
    assert_eq!(names, ["A", "B", "C"]);
    assert_eq!(page.next_cursor.as_deref(), Some("p3"));
    // The third page was never requested: discovery stopped at the bound.
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 2);
}

/// P3-4: an entry the local `max_tools` bound cuts mid-page is counted, not
/// silently discarded while the page is marked complete.
#[tokio::test]
async fn tools_list_counts_entries_cut_at_max_tools() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let info = ServerInfo {
        max_tools: 4,
        ..ServerInfo::default()
    };
    let client = kernel_mcp::client(transport, info);

    let page = client.list_tools(None).await.expect("list tools");
    let names: Vec<&str> = page.tools.iter().map(|tool| tool.name.as_str()).collect();
    assert_eq!(names, ["A", "B", "C", "D"]);
    assert!(page.truncated);
    assert_eq!(page.dropped, 1, "the cut entry must be counted");
    assert_eq!(page.next_cursor, None);
}

/// P1 / NP-2: a server that never finishes paginating is stopped by the page
/// bound and the entries gathered so far are returned with the resume cursor.
#[tokio::test]
async fn tools_list_page_bound_returns_partial_with_resume_cursor() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/spin-tools",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let page = client
        .list_tools(None)
        .await
        .expect("partial at the page bound");
    assert!(page.truncated, "a page-bound stop must be marked partial");
    assert_eq!(page.tools.len(), 20, "one tool per page for the page bound");
    assert_eq!(
        page.next_cursor.as_deref(),
        Some("spin19"),
        "the resume cursor must be the page after the last fetched one"
    );
    let hits = mock.state.list_hits.load(Ordering::SeqCst);
    assert_eq!(hits, 20, "pagination was not capped at the page bound");
}

/// P1: an echoed cursor is terminal, not another request.
#[tokio::test]
async fn tools_list_repeated_cursor_is_refused() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/repeat-cursor",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let err = client.list_tools(None).await.unwrap_err();
    match &err {
        McpError::Protocol { message, .. } => {
            assert!(
                message.as_str().contains("repeated a cursor"),
                "got {message}"
            )
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 2);
}

/// P1: an empty page that still carries a cursor cannot make progress.
#[tokio::test]
async fn tools_list_empty_page_with_cursor_is_refused() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport1 = transport(
        &mock,
        "/mcp/empty-tail",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport1, ServerInfo::default());

    let err = client.list_tools(None).await.unwrap_err();
    match &err {
        McpError::Protocol { message, .. } => assert!(
            message.as_str().contains("empty but carried a cursor"),
            "got {message}"
        ),
        other => panic!("expected Protocol, got {other:?}"),
    }
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 2);

    // A genuinely empty first page with a cursor is tolerated: the guard only
    // fires after the first page.
    let mock2 = spawn().await;
    let transport2 = transport(
        &mock2,
        "/mcp/spin-empty",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport2, ServerInfo::default());
    let err = client.list_tools(None).await.unwrap_err();
    match &err {
        McpError::Protocol { message, .. } => assert!(
            message.as_str().contains("empty but carried a cursor"),
            "got {message}"
        ),
        other => panic!("expected Protocol, got {other:?}"),
    }
    assert_eq!(mock2.state.list_hits.load(Ordering::SeqCst), 2);
}

/// P3: descriptor caps drop and count oversize/malformed entries.
#[tokio::test]
async fn descriptor_caps_drop_and_count_oversize_entries() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/oversize-tools",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let page = client.list_tools(None).await.expect("list tools");
    let names: Vec<&str> = page.tools.iter().map(|tool| tool.name.as_str()).collect();
    assert_eq!(names, ["GOOD"]);
    assert_eq!(page.dropped, 4, "oversize entries must not be silent");
}

/// NP-1: an over-cap `nextCursor` is a typed protocol error, never truncated,
/// and it is refused before the next (unbounded) request body is built.
#[tokio::test]
async fn tools_list_oversize_cursor_is_rejected() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport1 = transport(
        &mock,
        "/mcp/huge-cursor",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport1, ServerInfo::default());

    let err = client.list_tools(None).await.unwrap_err();
    match &err {
        McpError::Protocol { message, .. } => {
            assert!(message.as_str().contains("cursor"), "got {message}")
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
    assert_eq!(
        mock.state.list_hits.load(Ordering::SeqCst),
        1,
        "the over-cap cursor was echoed into another request body"
    );

    // An over-cap resume cursor is refused before any request goes out.
    let mock2 = spawn().await;
    let transport2 = transport(
        &mock2,
        "/mcp/huge-cursor",
        HeaderMap::new(),
        Limits::default(),
    );
    let client2 = kernel_mcp::client(transport2, ServerInfo::default());
    let huge = "s".repeat(500 * 1024);
    let err = client2.list_tools(Some(&huge)).await.unwrap_err();
    assert!(matches!(err, McpError::Protocol { .. }), "got {err:?}");
    assert_eq!(mock2.state.list_hits.load(Ordering::SeqCst), 0);
}

/// NP-1: one-character-mutating cursors are still bounded by the page cap, and
/// only a short hash of each cursor is retained.
#[tokio::test]
async fn tools_list_mutating_cursors_are_bounded_by_the_page_cap() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/mutating-cursor",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let page = client
        .list_tools(None)
        .await
        .expect("partial at the page cap");
    assert!(page.truncated);
    assert_eq!(page.tools.len(), 20);
    assert!(page.next_cursor.is_some());
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 20);
}

/// NP-1: a server that mints a fresh (near-cap) cursor per page cannot grow the
/// client's memory without bound.
#[tokio::test]
async fn tools_list_pagination_memory_is_bounded() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/mutating-big-cursor",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());
    client.initialize().await.expect("warm initialize");

    let page = client
        .list_tools(None)
        .await
        .expect("partial at the page cap");

    assert!(page.truncated);
    assert_eq!(page.tools.len(), 20);
    assert!(page.next_cursor.is_some());
    assert_eq!(
        mock.state.list_hits.load(Ordering::SeqCst),
        20,
        "pagination fetched past the page cap"
    );
}

/// NP-3: the aggregate deadline stops a server that answers every page just
/// inside the per-page budget, with a typed Timeout.
#[tokio::test]
async fn tools_list_aggregate_deadline_is_enforced() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/slow-paginate",
        HeaderMap::new(),
        Limits::default(),
    );
    let info = ServerInfo {
        list_tools_deadline: Duration::from_millis(150),
        ..ServerInfo::default()
    };
    let client = kernel_mcp::client(transport, info);
    client.initialize().await.expect("initialize");

    let started = Instant::now();
    let err = client.list_tools(None).await.unwrap_err();
    assert_eq!(err, McpError::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the aggregate deadline was not effective: {:?}",
        started.elapsed()
    );
    let hits = mock.state.list_hits.load(Ordering::SeqCst);
    assert!(
        hits < 20,
        "the page cap, not the deadline, stopped pagination ({hits} pages)"
    );
}
