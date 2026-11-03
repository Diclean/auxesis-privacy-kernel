//! stdio transport for a locally launched MCP server (M2.6 P1).
//!
//! Spawns one pinned command and speaks newline-delimited JSON-RPC 2.0 over
//! its stdin/stdout. A single bounded-channel writer owns stdin and completes
//! every accepted frame independently of caller cancellation. This is the
//! transport seam P1 adds; the broker and the
//! agent tools are deliberately **not** wired to it yet.
//!
//! # No shell, no inherited environment, no PATH lookup
//!
//! [`StdioCommand`] is the whole launch configuration: an **explicit** program
//! path, verbatim arguments and a small environment allowlist. The transport
//! never calls `sh -c`; it `execve`s the program directly, so an argument such
//! as `; rm -rf /` is passed as one literal byte string. A bare program name
//! (no path separator) is refused at construction, so nothing is resolved
//! through an implicit `PATH`. The child environment is `env_clear()`ed and
//! only allowlisted keys ([`ALLOWED_ENV_KEYS`]) are set from the spec: the
//! app's full environment, its API keys and its `AUXESIS_*` variables never
//! reach the child.
//!
//! # Bounds fail closed and stop the process
//!
//! Four bounds are enforced, and crossing any of them is terminal
//! ([`McpError::requires_connection_close`]) — the process is killed and
//! reaped, never resumed:
//!
//! * one frame (one newline-delimited line) is capped at
//!   [`StdioLimits::max_frame_bytes`];
//! * the accumulated stdout of the whole session is capped at
//!   [`StdioLimits::max_output_bytes`];
//! * a request has [`StdioLimits::request_timeout`] to answer;
//! * at most [`StdioLimits::max_inflight`] requests may be unanswered.
//!
//! # Lifecycle
//!
//! The process is spawned lazily on the first round trip, so `initialize` is
//! naturally the first frame. [`StdioTransport::shutdown`] closes stdin first
//! (EOF is the polite stop), then gives the child
//! [`StdioLimits::shutdown_grace`] to exit before it is killed; the reader
//! task always reaps the child. [`Drop`] closes stdin, wakes the reader and
//! lets it run the same terminal path, so no orphan and no zombie survives the
//! transport. Only the reader signals the process group, keeping the leader
//! unreaped across both signals so its pid/pgid cannot be recycled meanwhile.
//!
//! # Correlation is race-free
//!
//! A request's waiter is registered **before** its bytes are written and the
//! id is allocated monotonically and never reused, so a server that answers
//! immediately can never lose its response or have it delivered to another
//! caller. A response whose id matches no live waiter is rejected and counted.
//!
//! # Secrets never reach an error or a log
//!
//! Nothing here logs. [`StdioCommand`]'s `Debug` prints the program, the
//! **number** of arguments and the environment **keys** only — never an
//! argument value and never an environment value (a spec may carry a runtime
//! token). Server output is untrusted: callers mark it with
//! [`crate::tools::UNTRUSTED_MCP_TAG`] before it reaches a model.
//!
//! [`McpError::requires_connection_close`]: crate::McpError::requires_connection_close

mod command;
mod framing;
mod limits;
mod process;
mod shared;
mod transport;

pub use command::{
    env_key_declared, StdioCommand, ALLOWED_ENV_KEYS, DENIED_ENV_NAMES, DENIED_ENV_PREFIXES,
    RESERVED_ENV_PREFIXES,
};
pub use limits::{
    StdioLimits, DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_REQUEST_TIMEOUT, DEFAULT_SHUTDOWN_GRACE,
    MAX_ARGS, MAX_ENV_ENTRIES, MAX_OUTPUT_BYTES_CEILING, MAX_PENDING_REQUESTS,
};
pub use transport::StdioTransport;

/// The mandatory macOS Seatbelt wrapper for a stdio child.
///
/// Re-exported so a caller of [`StdioTransport::new`] can name the required
/// argument without depending on `kernel-broker` directly.
pub use kernel_broker::sandbox::StdioSandbox;

#[cfg(test)]
mod tests;
