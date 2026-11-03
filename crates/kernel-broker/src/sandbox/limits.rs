//! The sandbox's fixed limits: the helper path, the refusal messages and
//! the resource caps.

/// Where the platform sandbox helper lives on macOS.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Refusal shown to the model when sandboxing is required but unavailable.
pub const UNAVAILABLE_MESSAGE: &str = "shell refused: sandbox-exec is unavailable on this system; \
set `shell.allow_unsandboxed = true` in config.toml to run shell commands without a sandbox (not recommended)";

/// Refusal shown to the model when the config disables sandboxing without
/// also opting in to unsandboxed execution.
pub const DISABLED_MESSAGE: &str = "shell refused: `shell.sandbox = false` only takes effect together with \
`shell.allow_unsandboxed = true`; set both to run shell commands without a sandbox (not recommended)";

/// Highest number of open file descriptors inside a shell command.
pub const MAX_OPEN_FILES: u64 = 4096;

/// Largest file a shell command may create (per file, enforced with
/// `RLIMIT_FSIZE`): 1 GiB. This is a **per-file** cap, not a volume quota;
/// the workspace total is not metered in v1.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

/// Extra CPU-seconds a command may burn beyond its wall-clock timeout.
pub const CPU_LIMIT_GRACE_SECS: u64 = 30;

/// Memory watchdog budget for a command tree (sum of resident footprints).
/// `RLIMIT_AS`/`RLIMIT_DATA` are set best-effort too, but macOS rejects both,
/// so the watchdog is what actually contains a memory bomb there.
pub const MAX_COMMAND_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The fixed `PATH` every command runs with. Never inherited from the daemon:
/// the owner's `PATH` discloses the account name and private toolchain layout,
/// and every directory a sandboxed command may actually execute from is on
/// this list already.
pub const SANDBOX_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin";

/// Extra processes above the current user count an ACP terminal may create
/// (`RLIMIT_NPROC` headroom).
pub const MAX_EXTRA_PROCESSES: u64 = 64;
