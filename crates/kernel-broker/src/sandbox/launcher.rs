//! Building and running the sandboxed command: the child process, its
//! private temp dir and its captured output.

use super::error::LaunchError;
use super::home::real_home;
use super::limits::{CPU_LIMIT_GRACE_SECS, MAX_FILE_BYTES, SANDBOX_PATH};
use super::process::{mark_inherited_fds_close_on_exec, set_child_limits};
use super::profile::seatbelt_profile;
use super::shell::ShellSandbox;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;

/// A launched command plus the per-call resources it needs while it runs.
///
/// Keep this value alive until the child has been waited on: dropping it
/// removes the private temp dir used as `HOME`/`TMPDIR`. `stdout_capture` /
/// `stderr_capture` are unlinked private files in that temp dir; read them
/// after the child exits to get the command's output.
#[derive(Debug)]
pub struct Launched {
    /// The command to spawn (`sandbox-exec` wrapper, or `sh` when
    /// explicitly unsandboxed).
    pub command: tokio::process::Command,
    /// Per-call private temp dir (`HOME`, `TMPDIR`).
    pub temp: TempDir,
    /// Captured standard output (unlinked file, seek to start before reading).
    pub stdout_capture: std::fs::File,
    /// Captured standard error (unlinked file, seek to start before reading).
    pub stderr_capture: std::fs::File,
    /// Per-call marker file. The command inherits it as a **read-only** open
    /// descriptor (every other inherited descriptor is closed on exec); the
    /// process sweep identifies double-fork + `setsid()` orphans that
    /// reparented to launchd by the marker file's `(device, inode)`, which
    /// survives exec of any binary — even platform binaries whose environment
    /// `KERN_PROCARGS2` hides. A hostile command that closes all its
    /// descriptors escapes the sweep; the sandbox still confines whatever
    /// survives.
    pub marker_file: std::fs::File,
}

/// Build the command for `command_line`, sandboxed when possible.
///
/// Returns [`LaunchError::Unavailable`] (fail closed) when sandboxing is
/// requested but `sandbox-exec` is missing, unless
/// [`ShellSandbox::allow_unsandboxed`] is set — in which case the command
/// runs unsandboxed and the fallback is logged loudly. Likewise,
/// `sandbox.enabled = false` refuses unless `allow_unsandboxed` is set.
pub fn launch(
    command_line: &str,
    workspace: &Path,
    sandbox: &ShellSandbox,
    timeout: Duration,
) -> Result<Launched, LaunchError> {
    launch_with_limits(command_line, workspace, sandbox, timeout, MAX_FILE_BYTES, 0)
}

/// [`launch`] with explicit caps: `max_file_bytes` (`RLIMIT_FSIZE`) and, when
/// `max_processes > 0`, an `RLIMIT_NPROC` headroom above the current user
/// process count. The ACP terminal broker uses both.
pub fn launch_with_limits(
    command_line: &str,
    workspace: &Path,
    sandbox: &ShellSandbox,
    timeout: Duration,
    max_file_bytes: u64,
    max_processes: u64,
) -> Result<Launched, LaunchError> {
    let workspace = workspace.canonicalize()?;
    if workspace == Path::new("/") || !workspace.is_dir() {
        return Err(LaunchError::UnsafeWorkspace(
            workspace.display().to_string(),
        ));
    }

    let use_sandbox = if !sandbox.enabled {
        if !sandbox.allow_unsandboxed {
            tracing::error!(
                "shell refused: shell.sandbox = false without shell.allow_unsandboxed = true \
                 (workspace: {})",
                workspace.display()
            );
            return Err(LaunchError::SandboxDisabled);
        }
        tracing::error!(
            "shell: sandbox disabled by configuration and shell.allow_unsandboxed = true; \
             running commands UNSANDBOXED (workspace: {})",
            workspace.display()
        );
        false
    } else if sandbox.available() {
        true
    } else if sandbox.allow_unsandboxed {
        tracing::error!(
            "shell: sandbox-exec unavailable; running commands UNSANDBOXED because \
             shell.allow_unsandboxed = true (workspace: {})",
            workspace.display()
        );
        false
    } else {
        tracing::error!(
            "shell refused: sandbox-exec unavailable and shell.allow_unsandboxed is not set \
             (workspace: {})",
            workspace.display()
        );
        return Err(LaunchError::Unavailable);
    };

    // Per-call private temp dir: `HOME` and `TMPDIR` for the command, and the
    // only writable place besides the workspace. Failing to create it refuses
    // the call: falling back to the system temp root would open the whole
    // world. `tempfile` creates it with plain `create_dir` (0777 & ~umask),
    // so tighten it to 0700 explicitly — the private dir must not depend on
    // the daemon's umask.
    let temp = tempfile::Builder::new().prefix("aux-shell-").tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let temp_path = temp.path().canonicalize()?;

    // Output goes to unlinked private files: a background process holding the
    // stdout stream open can no longer keep the tool waiting for EOF, and the
    // command cannot tamper with (or symlink) a name we later reopen.
    let stdout_capture = tempfile::tempfile_in(&temp_path)?;
    let stderr_capture = tempfile::tempfile_in(&temp_path)?;
    let stdout_child = stdout_capture.try_clone()?;
    let stderr_child = stderr_capture.try_clone()?;
    // The marker file is read-only, empty and unlinked: inheriting it gives
    // the command no data and no write channel, but the sweep can find any
    // process that still holds it.
    let marker_file = tempfile::tempfile_in(&temp_path)?;

    let mut command = if use_sandbox {
        let profile = seatbelt_profile(
            &workspace,
            &temp_path,
            real_home().as_deref(),
            sandbox.network,
        )?;
        let mut command = tokio::process::Command::new(&sandbox.sandbox_exec);
        command.arg("-p").arg(profile);
        command.arg("/bin/sh");
        command
    } else {
        tokio::process::Command::new("/bin/sh")
    };
    command
        .arg("-c")
        .arg(command_line)
        .current_dir(&workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_child))
        .stderr(Stdio::from(stderr_child))
        .kill_on_drop(true);

    // Sanitised environment: never inherit the daemon's (or its parent's)
    // environment, which may hold API keys or tokens. Only a small allowlist
    // crosses into the command; `PATH` is the sandbox's own fixed value (the
    // owner's PATH leaks the account name and private toolchain layout and
    // buys the command nothing), and HOME/TMPDIR point at the private temp dir.
    command.env_clear();
    for key in ["LANG", "LC_ALL", "LC_CTYPE", "TERM"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .env("PATH", SANDBOX_PATH)
        .env("HOME", &temp_path)
        .env("TMPDIR", &temp_path)
        .env("SHELL", "/bin/sh");

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::process::CommandExt;
        let std_cmd = command.as_std_mut();
        let cpu_seconds = timeout.as_secs().saturating_add(CPU_LIMIT_GRACE_SECS);
        let marker_fd = marker_file.as_raw_fd();
        // New session (and process group): no controlling terminal, and a
        // pgid the timeout can SIGKILL as a group. Also drop every inherited
        // descriptor — except the read-only marker — and set best-effort
        // resource caps: all in the child, before exec, so the daemon itself
        // is untouched.
        unsafe {
            std_cmd.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                mark_inherited_fds_close_on_exec(marker_fd);
                set_child_limits(cpu_seconds, max_file_bytes, max_processes);
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (&marker_file, max_file_bytes, max_processes);

    Ok(Launched {
        command,
        temp,
        stdout_capture,
        stderr_capture,
        marker_file,
    })
}
