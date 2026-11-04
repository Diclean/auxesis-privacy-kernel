//! The transport handle: lazy spawn, the sole stdin writer, shutdown and drop.

use std::collections::HashMap;
use std::fmt;
use std::os::unix::process::CommandExt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use kernel_core::sync::lock_recover;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::{ChildStdin, Command};
use tokio::sync::{mpsc, oneshot, watch, Notify, Semaphore};

use crate::error::McpError;
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse};
use crate::Transport;

use super::command::StdioCommand;
use super::framing::encode;
use super::limits::{StdioLimits, MAX_PENDING_REQUESTS};
use super::process::read_loop;
use super::shared::{Exit, PendingGuard, Shared};
use super::snapshot::PreparedProgram;
use super::StdioSandbox;

/// One complete, newline-terminated frame accepted by the sole stdin writer.
struct WriteFrame {
    bytes: Vec<u8>,
    budget: Duration,
    complete: oneshot::Sender<Result<(), McpError>>,
}

/// One running stdio session. The writer task exclusively owns child stdin.
struct Conn {
    _snapshot: PreparedProgram,
    writer: mpsc::Sender<WriteFrame>,
    writer_task: tokio::task::JoinHandle<()>,
    reader: tokio::task::JoinHandle<()>,
}

/// A stdio transport for one pinned local MCP server.
pub struct StdioTransport {
    command: StdioCommand,
    verified_sha: String,
    limits: StdioLimits,
    /// When set, the child is spawned under the macOS Seatbelt profile shared
    /// with the shell tool (item 3): `~/.auxesis` and the store are denied, and
    /// network is allowed only when the server declared it. [`StdioTransport::new`]
    /// always sets it; only the crate-private `new_unsandboxed` leaves it empty.
    sandbox: Option<StdioSandbox>,
    pub(super) shared: Arc<Shared>,
    started: tokio::sync::Mutex<Option<Conn>>,
}

impl StdioTransport {
    /// Build a sandboxed transport over a validated pinned command.
    ///
    /// The Seatbelt wrapper is a **required** argument: no public constructor
    /// skips it, so another crate cannot reach the spawn path without a sandbox
    /// profile. On a host without Seatbelt the wrapper is inert, which is a
    /// platform property (`cfg(not(target_os = "macos"))`), never a caller
    /// switch; the daemon ships macOS only, and its launch path refuses a macOS
    /// spawn whose `sandbox-exec` is missing instead of dropping the profile.
    ///
    /// No process is spawned yet: the first [`Transport::round_trip`] starts it,
    /// so `initialize` is naturally the first frame on the wire.
    ///
    /// # The unsandboxed constructor is not public
    ///
    /// `StdioTransport::new_unsandboxed` is `pub(crate)`, so a downstream
    /// crate cannot call it:
    ///
    /// ```compile_fail
    /// # use kernel_mcp::{StdioCommand, StdioLimits, StdioTransport};
    /// let command = StdioCommand::new("/usr/bin/true").expect("absolute path");
    /// // error[E0624]: associated function `new_unsandboxed` is private
    /// let _ = StdioTransport::new_unsandboxed(command, StdioLimits::default());
    /// ```
    pub fn new(
        command: StdioCommand,
        limits: StdioLimits,
        sandbox: StdioSandbox,
    ) -> Result<Self, McpError> {
        let mut transport = Self::new_unsandboxed(command, limits)?;
        transport.sandbox = Some(sandbox);
        Ok(transport)
    }

    /// Build the raw transport with no sandbox profile.
    ///
    /// `pub(crate)` on purpose: this is the only unsandboxed constructor, and it
    /// must never be reachable from another crate. Integration tests outside
    /// this module use the `test-util`-gated [`StdioTransport::new_for_tests`]
    /// alias, which a production build (the app's daemon and CLI) never compiles.
    pub(crate) fn new_unsandboxed(
        command: StdioCommand,
        limits: StdioLimits,
    ) -> Result<Self, McpError> {
        command.validate()?;
        limits.validate()?;
        let verified_sha = command
            .verified_sha
            .clone()
            .unwrap_or_else(|| crate::config::binary_sha256(command.program()));
        let (exit, _receiver) = watch::channel(Exit::Running);
        Ok(Self {
            command,
            verified_sha,
            limits,
            sandbox: None,
            shared: Arc::new(Shared {
                pending: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
                unsolicited: AtomicUsize::new(0),
                pgid: AtomicUsize::new(0),
                inflight: Semaphore::new(limits.max_inflight.min(MAX_PENDING_REQUESTS)),
                dead: AtomicBool::new(false),
                output_bytes: AtomicUsize::new(0),
                kill: Notify::new(),
                exit,
            }),
            started: tokio::sync::Mutex::new(None),
        })
    }

    /// Build an unsandboxed transport for this crate's own integration tests.
    ///
    /// Compiled only with the `test-util` feature, which kernel-mcp's own
    /// `[dev-dependencies]` enables and **no** production crate (the app's daemon and CLI)
    /// does. The public constructor [`StdioTransport::new`] still requires a
    /// [`StdioSandbox`] in every build.
    #[cfg(feature = "test-util")]
    pub fn new_for_tests(command: StdioCommand, limits: StdioLimits) -> Result<Self, McpError> {
        Self::new_unsandboxed(command, limits)
    }

    /// The pinned command.
    pub fn command(&self) -> &StdioCommand {
        &self.command
    }

    /// Test-only: whether this transport was built with a Seatbelt sandbox.
    ///
    /// Used by the spawn-path acceptance test; it is not part of the public API
    /// and never influences the spawn.
    #[cfg(test)]
    pub(crate) fn has_sandbox(&self) -> bool {
        self.sandbox.is_some()
    }

    /// The session bounds.
    pub fn limits(&self) -> &StdioLimits {
        &self.limits
    }

    /// Whether a bound has failed the session or the process has exited.
    pub fn is_dead(&self) -> bool {
        self.shared.dead.load(Ordering::SeqCst)
    }

    /// Spawn the child if it is not running yet.
    pub async fn start(&self) -> Result<(), McpError> {
        self.ensure_started().await
    }

    /// Wait until the reader has reaped the child.
    ///
    /// Returns [`McpError::Timeout`] if the child is still running after
    /// `timeout`; that is a test/diagnostic helper, not a normal path.
    pub async fn wait_exit(&self, timeout: Duration) -> Result<std::process::ExitStatus, McpError> {
        // Subscribe before the first read: a `watch` receiver sees every value
        // sent after it exists, so an exit landing between the reads is never
        // missed (unlike a one-shot `notify_waiters`, which has no permit).
        let mut exit = self.shared.exit.subscribe();
        match exit.borrow_and_update().clone() {
            Exit::Reaped(status) => return Ok(status),
            Exit::Failed => return Err(McpError::ProcessGone),
            Exit::Running => {}
        }
        tokio::time::timeout(timeout, exit.changed())
            .await
            .map_err(|_| McpError::Timeout)?
            .map_err(|_| McpError::ProcessGone)?;
        let state = exit.borrow_and_update().clone();
        match state {
            Exit::Reaped(status) => Ok(status),
            // A terminal state other than a status means the reap itself failed.
            Exit::Failed | Exit::Running => Err(McpError::ProcessGone),
        }
    }

    /// Stop the child: close stdin, then kill after the grace period.
    ///
    /// Idempotent. The reader task always reaps the child, so no zombie is
    /// left behind; a transport dropped without this call is killed by
    /// [`Drop`].
    pub async fn shutdown(&self) -> Result<(), McpError> {
        let conn = self.started.lock().await.take();
        let Some(conn) = conn else {
            return Ok(());
        };
        // Close the writer channel: it drains accepted complete frames, then
        // drops stdin so EOF is the polite stop.
        drop(conn.writer);
        if self.wait_exit(self.limits.shutdown_grace).await.is_err() {
            self.shared.kill.notify_one();
            let _ = self.wait_exit(self.limits.shutdown_grace).await;
        }
        let _ = tokio::time::timeout(self.limits.shutdown_grace, conn.writer_task).await;
        // Let the reader finish reaping; it owns the `Child`.
        let _ = tokio::time::timeout(self.limits.shutdown_grace, conn.reader).await;
        Ok(())
    }

    /// Spawn the pinned command exactly once.
    async fn ensure_started(&self) -> Result<(), McpError> {
        let mut guard = self.started.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        if self.shared.dead.load(Ordering::SeqCst) {
            return Err(McpError::ProcessGone);
        }
        // Use the sealed system volume or a private, verified executable copy.
        let source = self.command.program().to_owned();
        let parent = self
            .sandbox
            .as_ref()
            .map_or_else(std::env::temp_dir, |sandbox| sandbox.temp_path().to_owned());
        let expected = self.verified_sha.clone();
        let snapshot = tokio::task::spawn_blocking(move || {
            PreparedProgram::create(&source, &parent, &expected)
        })
        .await
        .map_err(|_| McpError::ProcessGone)?
        .map_err(|err| McpError::Io { kind: err.kind() })?;
        let mut command = match &self.sandbox {
            Some(sandbox) => sandbox.command(snapshot.program(), &self.command.args),
            None => {
                let mut command = Command::new(snapshot.program());
                command.args(&self.command.args);
                command
            }
        };
        command
            // Protocol on stdin/stdout; stderr is discarded so a chatty server
            // can never leak a secret into an Auxesis log and can never
            // deadlock on a full stderr pipe.
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .env_clear()
            .kill_on_drop(true);
        command.as_std_mut().process_group(0);
        if let Some(sandbox) = &self.sandbox {
            command
                .env("HOME", sandbox.temp_path())
                .env("TMPDIR", sandbox.temp_path());
        }
        for (key, value) in &self.command.env {
            command.env(key, value);
        }
        for (key, value) in &self.command.declared_env {
            command.env(key, value);
        }
        // Verify the actual executable again immediately before spawning it.
        // Keep both disk hashing and the spawn on the blocking pool.
        let expected = self.verified_sha.clone();
        let (mut child, snapshot) = tokio::task::spawn_blocking(move || {
            if crate::config::binary_sha256(snapshot.program()) != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "program hash changed",
                ));
            }
            command.spawn().map(|child| (child, snapshot))
        })
        .await
        .map_err(|_| McpError::ProcessGone)?
        .map_err(|err| McpError::Io { kind: err.kind() })?;
        if let Some(pid) = child.id() {
            self.shared.pgid.store(pid as usize, Ordering::SeqCst);
        }
        let stdin = child.stdin.take().ok_or(McpError::ProcessGone)?;
        let stdout = child.stdout.take().ok_or(McpError::ProcessGone)?;
        let shared = Arc::clone(&self.shared);
        let limits = self.limits;
        let reader = tokio::spawn(read_loop(child, stdout, shared, limits));
        let (writer, receiver) = mpsc::channel(self.limits.max_inflight.min(MAX_PENDING_REQUESTS));
        let writer_task = tokio::spawn(write_loop(stdin, receiver, Arc::clone(&self.shared)));
        *guard = Some(Conn {
            _snapshot: snapshot,
            writer,
            writer_task,
            reader,
        });
        Ok(())
    }

    /// Submit one complete frame. After channel acceptance, the sole writer
    /// owns it until fully written or terminally failed, regardless of whether
    /// this caller is cancelled.
    async fn write_frame(&self, line: &[u8], budget: Duration) -> Result<(), McpError> {
        let writer = self
            .started
            .lock()
            .await
            .as_ref()
            .map(|conn| conn.writer.clone())
            .ok_or(McpError::ProcessGone)?;
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line);
        bytes.push(b'\n');
        let (complete, written) = oneshot::channel();
        match tokio::time::timeout(
            budget,
            writer.send(WriteFrame {
                bytes,
                budget,
                complete,
            }),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(McpError::ProcessGone),
            Err(_) => {
                self.mark_dead_and_stop().await;
                return Err(McpError::Timeout);
            }
        }
        match tokio::time::timeout(budget, written).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(McpError::ProcessGone),
            Err(_) => {
                self.mark_dead_and_stop().await;
                Err(McpError::Timeout)
            }
        }
    }

    /// Mark the session dead, signal a kill and wait (bounded) for the reap.
    async fn mark_dead_and_stop(&self) {
        self.shared.dead.store(true, Ordering::SeqCst);
        self.shared.kill.notify_one();
        if matches!(*self.shared.exit.borrow(), Exit::Running) {
            let _ = self.wait_exit(self.limits.shutdown_grace).await;
        }
    }
}

/// Sole owner of stdin. Once it dequeues a frame, it either writes the whole
/// frame or kills the session; it never advances to a later frame after a
/// partial write.
async fn write_loop(
    mut stdin: ChildStdin,
    mut frames: mpsc::Receiver<WriteFrame>,
    shared: Arc<Shared>,
) {
    while let Some(frame) = frames.recv().await {
        let outcome = tokio::time::timeout(frame.budget, async {
            stdin.write_all(&frame.bytes).await?;
            stdin.flush().await
        })
        .await;
        let result = match outcome {
            Ok(Ok(())) => Ok(()),
            // EPIPE means the child closed stdin before the frame landed: the
            // request never reached the server. A deliberate stop (an in-flight
            // bound or a kill) races exactly here, so report the honest "the
            // process is gone" rather than an opaque io failure.
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                Err(McpError::ProcessGone)
            }
            Ok(Err(error)) => Err(McpError::Io { kind: error.kind() }),
            Err(_) => Err(McpError::Timeout),
        };
        if result.is_err() {
            shared.dead.store(true, Ordering::SeqCst);
            shared.kill.notify_one();
        }
        let failed = result.is_err();
        let _ = frame.complete.send(result);
        if failed {
            break;
        }
    }
    // `stdin` is dropped here. When the sender channel was closed this is EOF;
    // on failure the child is already on the reader's terminal kill path.
}

impl fmt::Debug for StdioTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The command's own `Debug` already redacts argument and env values.
        f.debug_struct("StdioTransport")
            .field("command", &self.command)
            .field("limits", &self.limits)
            .field("dead", &self.is_dead())
            .finish()
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn stop(&self) {
        // Close stdin, then kill after the grace period; the reader reaps it.
        let _ = self.shutdown().await;
    }

    async fn round_trip(
        &self,
        req: JsonRpcRequest,
        timeout: Duration,
    ) -> Result<JsonRpcResponse, McpError> {
        // The effective budget never exceeds the configured one.
        let budget = timeout.min(self.limits.request_timeout);
        let deadline = tokio::time::Instant::now() + budget;
        self.ensure_started().await?;
        if self.shared.dead.load(Ordering::SeqCst) {
            return Err(McpError::ProcessGone);
        }

        let mut req = req;
        req.id = self
            .shared
            .next_id
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
            .map_err(|_| McpError::ProcessGone)?;
        let is_notification = req.method.starts_with("notifications/");
        let line = encode(&req, is_notification)?;
        if line.len() > self.limits.max_frame_bytes {
            // A frame bound is terminal: stop the process rather than leave a
            // half-used pipe the next caller could reason about.
            self.mark_dead_and_stop().await;
            return Err(McpError::FrameTooLarge {
                limit: self.limits.max_frame_bytes,
                seen: line.len(),
            });
        }

        if is_notification {
            // A notification has no answer: write it and report success.
            self.write_frame(
                &line,
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            )
            .await?;
            return Ok(JsonRpcResponse::success(req.id, Value::Null));
        }

        // Fail closed on the in-flight cap: queueing would let a caller build
        // an unbounded backlog against a stuck server.
        let permit = match self.shared.inflight.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                self.mark_dead_and_stop().await;
                return Err(McpError::TooManyInflight {
                    limit: self.limits.max_inflight.min(MAX_PENDING_REQUESTS),
                });
            }
        };

        let (tx, rx) = oneshot::channel();
        // Install the waiter *before* the request bytes leave, so an answer
        // that arrives while the write is still in flight (or immediately
        // after) always finds its correlation entry. Ids are monotonically
        // allocated and never reused, so an existing key here is a bug, not a
        // normal collision.
        let collision = {
            let mut pending = lock_recover(&self.shared.pending);
            match pending.entry(req.id) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(tx);
                    false
                }
                std::collections::hash_map::Entry::Occupied(_) => true,
            }
        };
        if collision {
            self.mark_dead_and_stop().await;
            drop(permit);
            return Err(McpError::ProcessGone);
        }
        let _pending = PendingGuard {
            shared: Arc::clone(&self.shared),
            id: req.id,
        };
        if let Err(err) = self
            .write_frame(
                &line,
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            )
            .await
        {
            // The frame never fully reached the server: drop the waiter so a
            // later response for this id is rejected as unknown.
            drop(permit);
            return Err(err);
        }

        let outcome = tokio::time::timeout_at(deadline, rx).await;
        drop(permit);
        match outcome {
            Ok(Ok(Ok(response))) => Ok(response),
            Ok(Ok(Err(err))) => Err(err),
            Ok(Err(_recv)) => Err(McpError::ProcessGone),
            Err(_) => {
                self.mark_dead_and_stop().await;
                Err(McpError::Timeout)
            }
        }
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        // No orphan, ever. Flip the flag and wake the reader; the reader owns
        // the `Child` and is the only place that may signal the process group.
        // It keeps the leader unreaped across both signals; Drop never signals
        // by number because a reaped pid/pgid may already have been recycled.
        self.shared.dead.store(true, Ordering::SeqCst);
        self.shared.kill.notify_one();
        let conn = self
            .started
            .try_lock()
            .ok()
            .and_then(|mut guard| guard.take());
        if let Some(conn) = conn {
            // Closing stdin is the polite stop: EOF lets a cooperative server
            // exit on its own before the reader's grace period expires.
            drop(conn.writer);
            drop(conn.writer_task);
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                // Let the reader run its terminal path (ordered group kills,
                // then reap). The await is moved off `Drop` because `Drop`
                // cannot block.
                runtime.spawn(async move {
                    let _ = conn.reader.await;
                });
            } else {
                // Detach rather than abort: if the original runtime is still
                // driving tasks on another thread, the reader remains the sole
                // owner of the child and will signal/reap it there.
                drop(conn.reader);
            }
        }
    }
}
