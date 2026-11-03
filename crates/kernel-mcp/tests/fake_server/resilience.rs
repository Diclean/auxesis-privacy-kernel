//! Resilience of the HTTP transport: timeouts, retries, redirects, frame
//! limits and the plaintext-origin refusal.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue};
use serde_json::json;

use kernel_mcp::{HttpTransport, Limits, McpError, ServerInfo};

use crate::helpers::{safe_args, serial, spawn, transport};

#[tokio::test]
async fn oversize_body_is_frame_too_large() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/big", HeaderMap::new(), Limits::tiny());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let err = client.initialize().await.unwrap_err();
    assert!(
        matches!(err, McpError::FrameTooLarge { limit: 64, .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn redirect_is_not_followed_and_key_is_not_forwarded() {
    let _guard = serial().await;
    let mock = spawn().await;
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("test-key-not-real"));
    let transport = transport(&mock, "/mcp/redirect", headers, Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let err = client.initialize().await.unwrap_err();
    assert!(
        matches!(err, McpError::Http { status } if (300..400).contains(&status)),
        "got {err:?}"
    );
    assert_eq!(mock.state.evil_hits.load(Ordering::SeqCst), 0);
    assert_eq!(mock.state.evil_key_hits.load(Ordering::SeqCst), 0);
}

/// P2: plaintext HTTP is refused off loopback; https and loopback are fine.
#[test]
fn plaintext_public_origin_is_refused() {
    let err = HttpTransport::new(
        "http://example.com/mcp",
        HeaderMap::new(),
        Limits::default(),
    )
    .err()
    .expect("plaintext public origin must be refused");
    assert!(matches!(err, McpError::OriginRefused { .. }), "got {err:?}");

    for origin in [
        "http://127.0.0.1:8080/mcp",
        "http://localhost:8080/mcp",
        "http://[::1]:8080/mcp",
        "https://mcp.example.com/mcp",
    ] {
        assert!(
            HttpTransport::new(origin, HeaderMap::new(), Limits::default()).is_ok(),
            "{origin} should be allowed"
        );
    }

    // S0's validated-limits surface is enforced at construction.
    let invalid = Limits {
        max_frame_bytes: 0,
        ..Limits::default()
    };
    let zero = HttpTransport::new("https://example.com/mcp", HeaderMap::new(), invalid)
        .err()
        .expect("invalid limits must be refused");
    assert!(
        matches!(zero, McpError::InvalidLimit { .. }),
        "got {zero:?}"
    );
}

#[tokio::test]
async fn five_hundred_is_typed_and_not_retried_on_list() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/500", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let err = client.list_tools(None).await.unwrap_err();
    assert!(matches!(err, McpError::Http { status: 500 }), "got {err:?}");
    // Exactly one request went out for the failed call: no retry on a status.
    assert_eq!(mock.state.flaky_hits.load(Ordering::SeqCst), 1);
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 0);

    // The route now answers 200, so a second explicit call succeeds. It walks
    // all three pages, so the flaky route sees three more requests.
    let page = client.list_tools(None).await.expect("second list");
    assert_eq!(page.tools.len(), 5);
    assert_eq!(mock.state.flaky_hits.load(Ordering::SeqCst), 4);
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 3);
}

/// P2/P3: the configured budget caps a per-call budget, and a timeout never
/// retries.
#[tokio::test]
async fn configured_timeout_is_effective_and_timeouts_do_not_retry() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = Arc::new(
        HttpTransport::new(&mock.url("/mcp/slow"), HeaderMap::new(), Limits::default())
            .expect("build transport")
            .with_timeout(Duration::from_millis(150))
            .expect("valid timeout"),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let started = Instant::now();
    let err = client.initialize().await.unwrap_err();
    assert_eq!(err, McpError::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the configured timeout was not effective: {:?}",
        started.elapsed()
    );
    assert_eq!(
        mock.state.slow_hits.load(Ordering::SeqCst),
        1,
        "a timeout must never be retried"
    );
}

/// P3: a dropped connection retries initialize/tools-list once, never a call.
#[tokio::test]
async fn connect_flap_retries_discovery_but_not_tools_call() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/flap", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let info = client.initialize().await.expect("initialize after flap");
    assert_eq!(info.name, "mock-server");
    assert_eq!(mock.state.flap_init.load(Ordering::SeqCst), 2);

    let page = client.list_tools(None).await.expect("list after flap");
    assert_eq!(page.tools.len(), 1);
    assert_eq!(page.tools[0].name, "FLAP");
    assert_eq!(mock.state.flap_list.load(Ordering::SeqCst), 2);

    let err = client
        .call_tool("TOOL", &safe_args(&json!({})), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(matches!(err, McpError::Protocol { .. }), "got {err:?}");
    assert_eq!(
        mock.state.flap_call.load(Ordering::SeqCst),
        1,
        "tools/call is never retried"
    );
}

/// NP-7: a zero or absurd per-request budget is a typed config error.
#[test]
fn with_timeout_rejects_zero_and_absurd() {
    for bad in [Duration::ZERO, Duration::from_secs(24 * 60 * 60 + 1)] {
        let err = HttpTransport::new(
            "http://127.0.0.1:9/mcp",
            HeaderMap::new(),
            Limits::default(),
        )
        .expect("build transport")
        .with_timeout(bad)
        .err()
        .expect("bad timeout must be refused");
        assert!(
            matches!(err, McpError::InvalidTimeout { .. }),
            "got {err:?}"
        );
    }
    assert!(HttpTransport::new(
        "http://127.0.0.1:9/mcp",
        HeaderMap::new(),
        Limits::default()
    )
    .expect("build transport")
    .with_timeout(Duration::from_secs(5))
    .is_ok());
}
