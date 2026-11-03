//! Hard bounds and budgets for one stdio session.

use std::time::Duration;

use crate::error::McpError;
use crate::limits::{
    check_limit, check_timeout, Limits, DEFAULT_MAX_FRAME_BYTES, DEFAULT_MAX_INFLIGHT,
};

/// Largest accepted accumulated stdout for one session: 64 MiB.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
/// Largest accepted accumulated-output bound: 4 GiB.
pub const MAX_OUTPUT_BYTES_CEILING: usize = 4 * 1024 * 1024 * 1024;
/// Default per-request budget for a stdio round trip.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default time the child has to honour stdin EOF before it is killed.
pub const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
/// Largest accepted number of pinned arguments.
pub const MAX_ARGS: usize = 1024;
/// Largest accepted number of pinned environment entries.
pub const MAX_ENV_ENTRIES: usize = 64;
/// Absolute cap on unanswered calls, independent of caller-supplied limits.
pub const MAX_PENDING_REQUESTS: usize = 64;

/// Hard bounds and budgets for one stdio session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdioLimits {
    /// Largest accepted single line (frame), in bytes.
    pub max_frame_bytes: usize,
    /// Largest accepted accumulated stdout over the whole session, in bytes.
    pub max_output_bytes: usize,
    /// Most requests that may be unanswered at once.
    pub max_inflight: usize,
    /// Budget for one request/notification frame write + answer.
    pub request_timeout: Duration,
    /// Time the child has to exit after stdin closes, before it is killed.
    pub shutdown_grace: Duration,
}

impl Default for StdioLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_inflight: DEFAULT_MAX_INFLIGHT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

impl StdioLimits {
    /// A deliberately tiny preset for tests.
    pub fn tiny() -> Self {
        Self {
            max_frame_bytes: 256,
            max_output_bytes: 4 * 1024,
            max_inflight: 1,
            request_timeout: Duration::from_millis(200),
            shutdown_grace: Duration::from_millis(500),
        }
    }

    /// Reject a zero or absurd bound before a process is ever spawned.
    pub fn validate(&self) -> Result<(), McpError> {
        check_limit(
            "max_frame_bytes",
            self.max_frame_bytes,
            Limits::MAX_FRAME_BYTES_CEILING,
        )?;
        check_limit(
            "max_output_bytes",
            self.max_output_bytes,
            MAX_OUTPUT_BYTES_CEILING,
        )?;
        check_limit(
            "max_inflight",
            self.max_inflight,
            Limits::MAX_INFLIGHT_CEILING,
        )?;
        check_timeout("request_timeout", self.request_timeout)?;
        check_timeout("shutdown_grace", self.shutdown_grace)?;
        Ok(())
    }
}
