//! Newline-delimited JSON-RPC framing and response correlation.

use std::sync::atomic::Ordering;

use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

use kernel_core::sync::lock_recover;

use crate::error::{McpError, INVALID_REQUEST, PARSE_ERROR};
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse};

use super::limits::StdioLimits;
use super::shared::Shared;

/// Encode one JSON-RPC envelope as a single line.
///
/// A notification omits the `id` member (JSON-RPC 2.0) and omits empty params.
pub(super) fn encode(req: &JsonRpcRequest, is_notification: bool) -> Result<Vec<u8>, McpError> {
    if is_notification {
        let mut envelope = Map::new();
        envelope.insert("jsonrpc".to_owned(), Value::String(req.jsonrpc.to_owned()));
        envelope.insert("method".to_owned(), Value::String(req.method.clone()));
        if req
            .params
            .as_object()
            .is_none_or(|params| !params.is_empty())
        {
            envelope.insert("params".to_owned(), req.params.clone());
        }
        serde_json::to_vec(&Value::Object(envelope))
            .map_err(|_| McpError::protocol(INVALID_REQUEST, "could not encode request"))
    } else {
        serde_json::to_vec(req)
            .map_err(|_| McpError::protocol(INVALID_REQUEST, "could not encode request"))
    }
}

/// Read one bounded, newline-terminated frame.
///
/// The aggregate counter advances on every byte **consumed** from the server,
/// so a server that answers with a stream of small valid lines is still stopped
/// and no byte is ever counted twice as it lingers in the read buffer.
pub(super) async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    limits: &StdioLimits,
    shared: &Shared,
) -> Result<Option<Vec<u8>>, McpError> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|err| McpError::Io { kind: err.kind() })?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Ok(Some(trim_eol(line)));
        }
        match available.iter().position(|byte| *byte == b'\n') {
            Some(position) => {
                if line.len() + position > limits.max_frame_bytes {
                    return Err(McpError::FrameTooLarge {
                        limit: limits.max_frame_bytes,
                        seen: line.len() + position,
                    });
                }
                // Count the whole frame, terminator included, before consuming.
                check_output(shared, limits, position + 1)?;
                line.extend_from_slice(&available[..position]);
                reader.consume(position + 1);
                return Ok(Some(trim_eol(line)));
            }
            None => {
                let len = available.len();
                if line.len() + len > limits.max_frame_bytes {
                    return Err(McpError::FrameTooLarge {
                        limit: limits.max_frame_bytes,
                        seen: line.len() + len,
                    });
                }
                check_output(shared, limits, len)?;
                line.extend_from_slice(available);
                reader.consume(len);
            }
        }
    }
}

/// Advance the session's accumulated-output counter, refusing a crossing.
fn check_output(shared: &Shared, limits: &StdioLimits, consumed: usize) -> Result<(), McpError> {
    let seen = shared.output_bytes.fetch_add(consumed, Ordering::SeqCst) + consumed;
    if seen > limits.max_output_bytes {
        return Err(McpError::OutputTooLarge {
            limit: limits.max_output_bytes,
            seen,
        });
    }
    Ok(())
}

/// Route one decoded line to the waiter with the matching request id.
///
/// A line that is not valid JSON is terminal (a stdio server must never write
/// anything but protocol to stdout). A server notification or a server→client
/// request is ignored: this client advertises no capability to answer one, and
/// ignoring it can never misattribute an answer.
pub(super) fn dispatch(line: &[u8], shared: &Shared) -> Result<(), McpError> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let value: Value = serde_json::from_slice(line)
        .map_err(|_| McpError::protocol(PARSE_ERROR, "invalid JSON from mcp server"))?;
    if value.get("method").is_some() {
        return Ok(());
    }
    let response: JsonRpcResponse = serde_json::from_value(value)
        .map_err(|_| McpError::protocol(PARSE_ERROR, "invalid JSON-RPC from mcp server"))?;
    let Some(id) = response.id.as_number() else {
        if shared.unsolicited.fetch_add(1, Ordering::SeqCst) + 1 >= 3 {
            return Err(McpError::protocol(
                INVALID_REQUEST,
                "too many unsolicited mcp responses",
            ));
        }
        return Ok(());
    };
    if let Some(sender) = lock_recover(&shared.pending).remove(&id) {
        let _ = sender.send(Ok(response));
    } else if shared.unsolicited.fetch_add(1, Ordering::SeqCst) + 1 >= 3 {
        // An id that matches no waiter is rejected and counted, never handed
        // to another caller.
        return Err(McpError::protocol(
            INVALID_REQUEST,
            "too many unsolicited mcp responses",
        ));
    }
    Ok(())
}

/// Fail every unanswered request with `err` (dropping a sender does the same,
/// but this keeps the precise reason).
pub(super) fn fail_pending(shared: &Shared, err: McpError) {
    let drained: Vec<_> = lock_recover(&shared.pending)
        .drain()
        .map(|(_, tx)| tx)
        .collect();
    for sender in drained {
        let _ = sender.send(Err(err.clone()));
    }
}

/// Strip one trailing CR from an already newline-stripped frame.
fn trim_eol(mut line: Vec<u8>) -> Vec<u8> {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    line
}
