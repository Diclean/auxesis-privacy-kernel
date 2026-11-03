//! The mock server's SSE routes: hostile line terminators, a leading BOM, a
//! wrong id and a 4 MiB line bomb.

use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use serde_json::{json, Value};

use crate::helpers::{json_result, tool, MockState};

pub(crate) async fn sse_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    let text = format!(
        "event: message\ndata: {}\n\nid: evt-42\ndata: {}\n\n",
        json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
        json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [tool("SSE_TOOL")], "nextCursor": Value::Null}})
    );
    ([(header::CONTENT_TYPE, "text/event-stream")], text).into_response()
}

/// A complete SSE stream with an interleaved notification, using `term` as the
/// line terminator.
fn eol_sse_body(term: &str, id: u64) -> String {
    let notif = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}).to_string();
    let resp = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"tools": [tool("EOL_TOOL")], "nextCursor": Value::Null}
    })
    .to_string();
    format!("event: message{term}data: {notif}{term}{term}id: evt-9{term}data: {resp}{term}{term}")
}

pub(crate) async fn sse_lf_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    (
        [(header::CONTENT_TYPE, "text/event-stream")],
        eol_sse_body("\n", id),
    )
        .into_response()
}

pub(crate) async fn sse_crlf_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    (
        [(header::CONTENT_TYPE, "text/event-stream")],
        eol_sse_body("\r\n", id),
    )
        .into_response()
}

pub(crate) async fn sse_cr_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    (
        [(header::CONTENT_TYPE, "text/event-stream")],
        eol_sse_body("\r", id),
    )
        .into_response()
}

pub(crate) async fn sse_no_id_handler(axum::Json(_body): axum::Json<Value>) -> Response {
    let text = format!(
        "data: {}\n\n",
        json!({"jsonrpc": "2.0", "result": {"tools": []}})
    );
    ([(header::CONTENT_TYPE, "text/event-stream")], text).into_response()
}

pub(crate) async fn sse_wrong_id_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0) + 1;
    let text = format!(
        "data: {}\n\n",
        json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}})
    );
    ([(header::CONTENT_TYPE, "text/event-stream")], text).into_response()
}

pub(crate) async fn sse_bomb_handler(axum::Json(body): axum::Json<Value>) -> Response {
    // The first `initialize` is answered normally so the test can warm the
    // connection and measure only the bomb; the notification is a 202.
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    if method == "initialize" {
        return json_result(
            body.get("id").and_then(Value::as_u64),
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "serverInfo": { "name": "bomb-server", "version": "0.1.0" }
            }),
            false,
        );
    }
    if method.starts_with("notifications/") {
        return StatusCode::ACCEPTED.into_response();
    }

    // One SSE line of ~4 MiB, streamed in 64 KiB chunks so the server itself
    // never holds the explosion in memory.
    let head = Bytes::from_static(b"data: ");
    let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
    let mut items: Vec<Result<Bytes, Infallible>> = Vec::with_capacity(1 + 64);
    items.push(Ok(head));
    for _ in 0..64 {
        items.push(Ok(chunk.clone()));
    }
    let body = Body::from_stream(stream::iter(items));
    ([(header::CONTENT_TYPE, "text/event-stream")], body).into_response()
}

/// NP-6: the stream begins with a UTF-8 BOM before the first `data:` line.
pub(crate) async fn sse_bom_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    let text = format!(
        "\u{feff}data: {}\n\n",
        json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [tool("BOM_TOOL")], "nextCursor": Value::Null}})
    );
    ([(header::CONTENT_TYPE, "text/event-stream")], text).into_response()
}

/// NP-9: the SSE `id:` carries ANSI escapes and crosses the byte cap.
pub(crate) async fn sse_evil_id_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    let evil = format!("\u{1b}[31m{}", "z".repeat(600));
    let text = format!(
        "id: {evil}\ndata: {}\n\n",
        json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [tool("EVIL_ID")], "nextCursor": Value::Null}})
    );
    ([(header::CONTENT_TYPE, "text/event-stream")], text).into_response()
}
