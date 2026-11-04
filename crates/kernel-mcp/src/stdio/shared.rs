//! State shared between the transport and its reader task.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex};

use tokio::sync::{oneshot, watch, Notify, Semaphore};

use kernel_core::sync::lock_recover;

#[cfg(test)]
pub(super) use kernel_core::sync::lock_recover as lock;

use crate::error::McpError;
use crate::jsonrpc::JsonRpcResponse;

/// State shared between the transport and its reader task.
pub(super) struct Shared {
    /// In-flight requests, keyed by their JSON-RPC id.
    ///
    /// The entry is installed **before** the request is written, so a server
    /// that answers immediately can never race ahead of the correlation table:
    /// the reader either finds the waiter or rejects the id as unknown, but a
    /// response can never be lost or handed to another caller.
    pub(super) pending: Mutex<HashMap<u64, oneshot::Sender<Result<JsonRpcResponse, McpError>>>>,
    pub(super) next_id: AtomicU64,
    pub(super) unsolicited: AtomicUsize,
    pub(super) pgid: AtomicUsize,
    /// At most `max_inflight` unanswered requests.
    pub(super) inflight: Semaphore,
    /// Set once the process is gone or a bound has failed the session.
    pub(super) dead: AtomicBool,
    /// Total stdout bytes read over the session.
    pub(super) output_bytes: AtomicUsize,
    /// Signals the reader to kill the child now.
    pub(super) kill: Notify,
    /// The reaped exit state, sent once (see [`Exit`]).
    pub(super) exit: watch::Sender<Exit>,
}

/// Removes a correlation entry on every exit path, including future drop.
pub(super) struct PendingGuard {
    pub(super) shared: Arc<Shared>,
    pub(super) id: u64,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        lock_recover(&self.shared.pending).remove(&self.id);
    }
}

/// How the reader task ended for the child process.
///
/// The watch channel starts at [`Exit::Running`], so a waiter can always tell
/// "not yet" from "the reap itself failed" without a second flag or a race.
#[derive(Debug, Clone)]
pub(super) enum Exit {
    /// The child has not been reaped yet.
    Running,
    /// The reader killed the child but `wait` failed.
    Failed,
    /// The reaped status.
    Reaped(std::process::ExitStatus),
}
