//! The mock server's pagination routes: cursors that never repeat, pages that
//! never end and cursors that are too large.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use crate::helpers::{json_result, tool, MockState};

/// Every page is empty and carries a fresh cursor: the empty-page guard must
/// stop the client on page two.
pub(crate) async fn spin_empty_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({ "tools": [], "nextCursor": format!("spin{n}") }),
        false,
    )
}

/// Every page has one tool and a fresh cursor, and never reaches `max_tools`:
/// the hard page bound must stop the client.
pub(crate) async fn spin_tools_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({ "tools": [tool(&format!("SPIN_{n}"))], "nextCursor": format!("spin{n}") }),
        false,
    )
}

/// Every page advertises the same cursor.
pub(crate) async fn repeat_cursor_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({ "tools": [tool("REPEAT")], "nextCursor": "loop" }),
        false,
    )
}

/// Page one is non-empty; page two is empty but still carries a cursor.
pub(crate) async fn empty_tail_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    if n == 0 {
        json_result(
            id,
            json!({ "tools": [tool("FIRST")], "nextCursor": "e1" }),
            false,
        )
    } else {
        json_result(id, json!({ "tools": [], "nextCursor": "e2" }), false)
    }
}

/// Shared preamble for the hostile discovery routes: answer `initialize`
/// normally and accept the completion notification, so a test can warm the
/// connection without polluting the `tools/list` hit counter.
fn discovery_preamble(body: &Value) -> Option<Response> {
    match body.get("method").and_then(Value::as_str).unwrap_or("") {
        "initialize" => Some(json_result(
            body.get("id").and_then(Value::as_u64),
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "serverInfo": { "name": "cursor-mock", "version": "0.1.0" }
            }),
            false,
        )),
        method if method.starts_with("notifications/") => {
            Some(StatusCode::ACCEPTED.into_response())
        }
        _ => None,
    }
}

/// NP-1: a page advertises a ~500 KiB cursor, far above the 4 KiB cap.
pub(crate) async fn huge_cursor_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    if let Some(response) = discovery_preamble(&body) {
        return response;
    }
    state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({ "tools": [tool("HUGE")], "nextCursor": "H".repeat(500 * 1024) }),
        false,
    )
}

/// A distinct cursor where one character mutates per page.
fn one_char_mutation(n: usize) -> String {
    let mut bytes = vec![b'a'; 64];
    bytes[n % 64] = b'A' + (n % 26) as u8;
    String::from_utf8(bytes).expect("ascii cursor")
}

/// NP-1: every page mints a cursor that differs from the previous one by a
/// single character, so a text-based seen-set would keep growing.
pub(crate) async fn mutating_cursor_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    if let Some(response) = discovery_preamble(&body) {
        return response;
    }
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({ "tools": [tool(&format!("M{n}"))], "nextCursor": one_char_mutation(n) }),
        false,
    )
}

/// NP-1: as above, but each distinct cursor sits just under the byte cap, so a
/// client that retained the text of every cursor would hold ~80 KiB of cursors.
pub(crate) async fn mutating_big_cursor_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    if let Some(response) = discovery_preamble(&body) {
        return response;
    }
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    let mut cursor = "c".repeat(4000);
    cursor.replace_range(n % 100..n % 100 + 1, "Z");
    json_result(
        id,
        json!({ "tools": [tool(&format!("B{n}"))], "nextCursor": cursor }),
        false,
    )
}

/// NP-3: answers each `tools/list` after a delay, always with a fresh cursor,
/// so only an aggregate deadline can stop the pagination.
pub(crate) async fn slow_paginate_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    if let Some(response) = discovery_preamble(&body) {
        return response;
    }
    let id = body.get("id").and_then(Value::as_u64);
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(60)).await;
    json_result(
        id,
        json!({ "tools": [tool(&format!("S{n}"))], "nextCursor": format!("sp{n}") }),
        false,
    )
}
