//! Child-process lifecycle: terminal stops, group signals and the reap.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::BufReader;
use tokio::process::{Child, ChildStdout};

use crate::error::McpError;

use super::framing::{dispatch, fail_pending, read_frame};
use super::limits::StdioLimits;
use super::shared::{Exit, Shared};

/// The reader task: bounded frames in, correlated answers out, child reaped.
pub(super) async fn read_loop(
    child: Child,
    stdout: ChildStdout,
    shared: Arc<Shared>,
    limits: StdioLimits,
) {
    let mut child = child;
    let mut reader = BufReader::new(stdout);
    let failure = loop {
        tokio::select! {
            _ = shared.kill.notified() => break None,
            frame = read_frame(&mut reader, &limits, &shared) => match frame {
                Ok(Some(line)) => {
                    if let Err(err) = dispatch(&line, &shared) {
                        break Some(err);
                    }
                }
                Ok(None) => break None, // EOF: the server closed stdout
                Err(err) => break Some(err),
            },
        }
    };
    // Terminal for every exit path: stop and reap, then fail any waiter with
    // the precise reason (never let a caller hang on a dead pipe).
    //
    // Keep the leader unreaped across both group signals. A zombie pins its pid
    // (and therefore pgid), so the number cannot be recycled between SIGTERM
    // and SIGKILL. This task is the sole owner of the Child and its reap.
    let pgid = shared.pgid.load(Ordering::SeqCst);
    if pgid != 0 && child_is_unreaped(pgid as libc::pid_t) {
        signal_group(pgid as libc::pid_t, libc::SIGTERM);
        let still_owned = wait_for_leader_exit(pgid as libc::pid_t, limits.shutdown_grace).await;
        if still_owned {
            // Unconditional with respect to leader state: waitid used WNOWAIT,
            // so even an exited leader is still an unreaped zombie pinning pgid.
            signal_group(pgid as libc::pid_t, libc::SIGKILL);
        }
    }
    let status = child.wait().await.ok();
    shared.dead.store(true, Ordering::SeqCst);
    let err = failure.unwrap_or(McpError::ProcessGone);
    fail_pending(&shared, err);
    // `send_replace`, not `send`: the transport may hold the only sender and a
    // `send` with zero receivers would drop the terminal state, leaving a
    // later `wait_exit` waiting forever. `send_replace` always stores it.
    let _ = shared.exit.send_replace(match status {
        Some(status) => Exit::Reaped(status),
        None => Exit::Failed,
    });
}

/// Probe exit without reaping the leader (`WNOWAIT` keeps its pid/pgid pinned).
/// `Some(true)` means exited but still waitable, `Some(false)` means running,
/// and `None` means ownership cannot be established (including ECHILD).
fn waitid_observation(pid: libc::pid_t) -> Option<bool> {
    loop {
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: `info` is a valid writable siginfo_t, and waitid receives only
        // scalar identifiers/flags. WNOWAIT explicitly leaves the child waitable.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            // SAFETY: si_pid is read only after waitid initialised `info`.
            return Some(unsafe { info.si_pid() != 0 });
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return None;
        }
    }
}

pub(super) fn child_is_unreaped(pid: libc::pid_t) -> bool {
    waitid_observation(pid).is_some()
}

/// Return false only if another path has already reaped (or ownership cannot
/// safely be established); otherwise wait up to `grace` without consuming exit.
pub(super) async fn wait_for_leader_exit(pid: libc::pid_t, grace: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        match waitid_observation(pid) {
            Some(true) => return true,
            Some(false) => {}
            None => return false,
        }
        if tokio::time::Instant::now() >= deadline {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Signal a process group whose leader is still owned and unreaped by the
/// reader. Its zombie pid prevents group-id recycling until the later wait.
pub(super) fn signal_group(pgid: libc::pid_t, signal: i32) {
    // SAFETY: negative pid selects the pinned child process group; no pointers
    // are passed, and the sole Child owner does not reap until after SIGKILL.
    unsafe {
        libc::kill(-pgid, signal);
    }
}
