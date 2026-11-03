//! S1 acceptance: the Streamable HTTP transport and `McpClient` against a local
//! axum mock server. **Offline only** — every socket is on `127.0.0.1`, there is
//! no real key, no Keychain and no external host.
//!
//! The mock deliberately serves hostile routes: an oversize JSON body, a 4 MiB
//! SSE line bomb, a 500-then-200 endpoint, a redirect to a second origin, a
//! missing `Mcp-Session-Id`, a `tools/list_changed` notification, a pagination
//! server that never ends, a connection flap, a slow endpoint, and response
//! bodies whose id does not match the request.

mod discovery;
mod helpers;
mod page_routes;
mod protocol;
mod resilience;
mod routes;
mod session;
mod sse;
mod sse_routes;
mod tools_call;
