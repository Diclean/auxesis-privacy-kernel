//! Shared harness: the mock server, its counters and the reply builders that
//! every test module uses.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use serde_json::{json, Map, Value};

use kernel_mcp::{HttpTransport, Limits};

use crate::page_routes::{
    empty_tail_handler, huge_cursor_handler, mutating_big_cursor_handler, mutating_cursor_handler,
    repeat_cursor_handler, slow_paginate_handler, spin_empty_handler, spin_tools_handler,
};
use crate::routes::{
    bad_version_handler, big_handler, evil_handler, evil_info_handler, flaky_handler, flap_handler,
    main_handler, no_id_handler, old_version_handler, oversize_tools_handler, redirect_handler,
    session_error_handler, session_handler, session_long_handler, slow_handler, wrong_id_handler,
};
use crate::sse_routes::{
    sse_bom_handler, sse_bomb_handler, sse_cr_handler, sse_crlf_handler, sse_evil_id_handler,
    sse_handler, sse_lf_handler, sse_no_id_handler, sse_wrong_id_handler,
};

/// The grant-bound arguments every `tools/call` in this file sends: the HTTP
/// path accepts only a `SafeValue`, so the test admits the call first.
pub(crate) fn safe_args(args: &Value) -> kernel_privacy::SafeValue {
    use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
    let ctx = Context {
        destination: Destination::Vendor("mock".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::B13, PrivacyMode::Open, &ctx) else {
        panic!("B13 is admitted in open mode");
    };
    let mut gate = kernel_privacy::Gate::for_grant(&grant, [7u8; 32]);
    gate.value(args).expect("arguments are admitted").0
}

/// Tests run on several threads; the memory-bound test reads process resident
/// size, so every test in this file takes the lock to keep allocations serial.
pub(crate) static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL.lock().await
}

/// Shared counters so a test can prove how many requests actually went out.
#[derive(Default)]
pub(crate) struct MockState {
    pub(crate) init_hits: AtomicUsize,
    pub(crate) list_hits: AtomicUsize,
    pub(crate) call_hits: AtomicUsize,
    pub(crate) list_with_session: AtomicUsize,
    pub(crate) list_with_protocol_header: AtomicUsize,
    pub(crate) notification_hits: AtomicUsize,
    pub(crate) notification_with_id: AtomicUsize,
    pub(crate) flaky_hits: AtomicUsize,
    pub(crate) evil_hits: AtomicUsize,
    pub(crate) evil_key_hits: AtomicUsize,
    pub(crate) evil_port: AtomicUsize,
    pub(crate) flap_init: AtomicUsize,
    pub(crate) flap_list: AtomicUsize,
    pub(crate) flap_call: AtomicUsize,
    pub(crate) slow_hits: AtomicUsize,
}

pub(crate) struct Mock {
    port: u16,
    pub(crate) state: Arc<MockState>,
    _handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Mock {
    pub(crate) fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

pub(crate) async fn spawn() -> Mock {
    let evil_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind evil");
    let evil_port = evil_listener.local_addr().expect("evil addr").port();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let port = listener.local_addr().expect("mock addr").port();

    let state = Arc::new(MockState {
        evil_port: AtomicUsize::new(usize::from(evil_port)),
        ..MockState::default()
    });

    let app = Router::new()
        .route("/mcp", post(main_handler))
        .route("/mcp/no-session", post(main_handler))
        .route("/mcp/session", post(session_handler))
        .route("/mcp/session-error", post(session_error_handler))
        .route("/mcp/session-long", post(session_long_handler))
        .route("/mcp/500", post(flaky_handler))
        .route("/mcp/redirect", post(redirect_handler))
        .route("/mcp/big", post(big_handler))
        .route("/mcp/sse", post(sse_handler))
        .route("/mcp/sse-lf", post(sse_lf_handler))
        .route("/mcp/sse-crlf", post(sse_crlf_handler))
        .route("/mcp/sse-cr", post(sse_cr_handler))
        .route("/mcp/sse-no-id", post(sse_no_id_handler))
        .route("/mcp/sse-wrong-id", post(sse_wrong_id_handler))
        .route("/mcp/sse-bomb", post(sse_bomb_handler))
        .route("/mcp/no-id", post(no_id_handler))
        .route("/mcp/wrong-id", post(wrong_id_handler))
        .route("/mcp/spin-empty", post(spin_empty_handler))
        .route("/mcp/spin-tools", post(spin_tools_handler))
        .route("/mcp/repeat-cursor", post(repeat_cursor_handler))
        .route("/mcp/empty-tail", post(empty_tail_handler))
        .route("/mcp/huge-cursor", post(huge_cursor_handler))
        .route("/mcp/mutating-cursor", post(mutating_cursor_handler))
        .route(
            "/mcp/mutating-big-cursor",
            post(mutating_big_cursor_handler),
        )
        .route("/mcp/slow-paginate", post(slow_paginate_handler))
        .route("/mcp/bad-version", post(bad_version_handler))
        .route("/mcp/old-version", post(old_version_handler))
        .route("/mcp/evil-info", post(evil_info_handler))
        .route("/mcp/sse-bom", post(sse_bom_handler))
        .route("/mcp/sse-evil-id", post(sse_evil_id_handler))
        .route("/mcp/flap", post(flap_handler))
        .route("/mcp/slow", post(slow_handler))
        .route("/mcp/oversize-tools", post(oversize_tools_handler))
        .with_state(state.clone());
    let evil = Router::new()
        .fallback(evil_handler)
        .with_state(state.clone());

    let main_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let evil_handle = tokio::spawn(async move {
        let _ = axum::serve(evil_listener, evil).await;
    });

    Mock {
        port,
        state,
        _handles: vec![main_handle, evil_handle],
    }
}

pub(crate) fn respond(
    state: &MockState,
    headers: &HeaderMap,
    body: &Value,
    with_session: bool,
) -> Response {
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let id = body.get("id").and_then(Value::as_u64);
    match method {
        "initialize" => {
            state.init_hits.fetch_add(1, Ordering::SeqCst);
            json_result(
                id,
                json!({
                    "protocolVersion": "2025-11-25",
                    "capabilities": { "tools": { "listChanged": true } },
                    "serverInfo": { "name": "mock-server", "version": "0.1.0" },
                    "instructions": "mock"
                }),
                with_session,
            )
        }
        "notifications/initialized" => {
            state.notification_hits.fetch_add(1, Ordering::SeqCst);
            if body.get("id").is_some() {
                state.notification_with_id.fetch_add(1, Ordering::SeqCst);
            }
            StatusCode::ACCEPTED.into_response()
        }
        "tools/list" => {
            state.list_hits.fetch_add(1, Ordering::SeqCst);
            if headers.contains_key("mcp-session-id") {
                state.list_with_session.fetch_add(1, Ordering::SeqCst);
            }
            if headers
                .get("mcp-protocol-version")
                .and_then(|value| value.to_str().ok())
                == Some("2025-11-25")
            {
                state
                    .list_with_protocol_header
                    .fetch_add(1, Ordering::SeqCst);
            }
            let cursor = body
                .get("params")
                .and_then(|params| params.get("cursor"))
                .and_then(Value::as_str);
            let (tools, next) = match cursor {
                None => (json!([tool("A"), tool("B")]), Some("p2")),
                Some("p2") => (json!([tool("C")]), Some("p3")),
                Some(_) => (json!([tool("D"), tool("E")]), None),
            };
            json_result(
                id,
                json!({ "tools": tools, "nextCursor": next }),
                with_session,
            )
        }
        "tools/call" => {
            state.call_hits.fetch_add(1, Ordering::SeqCst);
            let name = body
                .get("params")
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            match name {
                "MISSING" => json_error(id, -32602, "unknown tool: MISSING"),
                "BADARGS" => json_error(id, -32602, "invalid arguments for tool BADARGS"),
                "FAILS" => json_result(
                    id,
                    json!({ "content": [{ "type": "text", "text": "boom" }], "isError": true }),
                    false,
                ),
                _ => json_result(
                    id,
                    json!({ "content": [{ "type": "text", "text": "ok" }], "isError": false }),
                    false,
                ),
            }
        }
        other => json_error(id, -32601, &format!("unknown method: {other}")),
    }
}

pub(crate) fn tool(name: &str) -> Value {
    json!({ "name": name, "description": format!("tool {name}"), "inputSchema": { "type": "object" } })
}

pub(crate) fn json_result(id: Option<u64>, result: Value, with_session: bool) -> Response {
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".to_owned(), json!("2.0"));
    if let Some(id) = id {
        envelope.insert("id".to_owned(), json!(id));
    }
    envelope.insert("result".to_owned(), result);
    respond_with(Value::Object(envelope), with_session)
}

pub(crate) fn json_error(id: Option<u64>, code: i64, message: &str) -> Response {
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".to_owned(), json!("2.0"));
    if let Some(id) = id {
        envelope.insert("id".to_owned(), json!(id));
    }
    envelope.insert(
        "error".to_owned(),
        json!({ "code": code, "message": message }),
    );
    respond_with(Value::Object(envelope), false)
}

pub(crate) fn respond_with(envelope: Value, with_session: bool) -> Response {
    let mut response = (
        [(header::CONTENT_TYPE, "application/json")],
        envelope.to_string(),
    )
        .into_response();
    if with_session {
        response
            .headers_mut()
            .insert("mcp-session-id", HeaderValue::from_static("sess_mock_1"));
    }
    response
}

pub(crate) fn transport(
    mock: &Mock,
    path: &str,
    headers: HeaderMap,
    limits: Limits,
) -> Arc<HttpTransport> {
    Arc::new(HttpTransport::new(&mock.url(path), headers, limits).expect("build transport"))
}
