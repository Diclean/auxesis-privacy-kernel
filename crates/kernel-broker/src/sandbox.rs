//! macOS Seatbelt sandbox for the `shell` tool.
//!
//! The shell tool never runs a command directly while sandboxing is on:
//! [`launch`] builds `sandbox-exec -p <profile> /bin/sh -c <cmd>` with a
//! deny-by-default profile. The profile is deliberately small:
//!
//! - **exec**: `/usr`, `/bin`, `/sbin`, `/System`, the Command Line Tools (or
//!   the full Xcode developer directory when one is selected) and the Python
//!   framework, plus only the *program* directories inside the package
//!   prefixes (`bin`, `sbin`, `opt`, `Cellar`, `lib`, `include`, `share`) —
//!   never the whole prefix. `var`, `etc` and `Caskroom` under
//!   `/opt/homebrew` and `/usr/local` stay unreadable, so a package manager's
//!   logs, datasets, git checkout and config files are not exposed; the only
//!   exceptions are explicit read-backs *after* the deny for the specific
//!   paths common toolchains need to start (Homebrew's OpenSSL config and CA
//!   bundle, Homebrew's own `Library/Homebrew` code so `brew --version`/`list`/
//!   `info` work, system Ruby's gems tree) — never a whole `etc` or `Library`
//!   directory. The full-Xcode grant is a **shell tool** affordance: the
//!   stdio (MCP) sandbox in [`StdioSandbox`] never carries it, so an MCP
//!   server gets exactly the profile it had before the Xcode grant existed;
//! - **read**: the same system trees, the dyld cache and timezone data under
//!   `/private/var/db`, a handful of `/etc` files common commands need
//!   (`hosts`, `resolv.conf`, `localtime`, `services`, `protocols`, `ssl`),
//!   `/dev`, and the workspace + per-call temp dir. Nothing else — in
//!   particular not `/private/var/db` or `/Library` as a whole, so the unified
//!   log store, `/Library/Logs`, the system keychains and other machine state
//!   stay closed;
//! - **sysctl / process-info**: both are globally denied at the end of the
//!   profile (last-match-wins), so `lsof`, `ps`-equivalents, `launchctl print`
//!   and `sysctl -a` cannot enumerate the user's processes, open files or
//!   kernel state. A small set of non-sensitive sysctl names (CPU count, RAM
//!   size, page size, `uname` identity) is allowed back after the deny, and
//!   `process-info*` is allowed back for **self** only, which Foundation needs
//!   to start (`sw_vers`, `osascript`) but which reveals nothing about other
//!   processes;
//! - **write**: only the workspace and the per-call private temp dir (also
//!   `HOME`/`TMPDIR`), plus the standard `/dev` sinks;
//! - **network**: off by default (all sockets denied, loopback included);
//!   `network = true` allows **all** sockets for v1 — there is no narrower
//!   host/port allowlist, documented on [`ShellSandbox::network`];
//! - **sensitive paths**: the Auxesis home, `.ssh`, `.aws`, `.config`,
//!   `.gnupg`, `.docker`, `.kube`, Keychains, Messages/Mail/Safari/Cookies
//!   and browser profile dirs are denied explicitly, last, so they win over
//!   the broader system reads. A workspace that is equal to, inside, or an
//!   ancestor of any of them is refused up front (a workspace inside
//!   `~/.auxesis` itself stays allowed — that is where agents live).
//!
//! Path filters are matched by the kernel against *canonical* paths, while
//! symlinks are resolved during the check — so the workspace, temp dir and
//! home are canonicalised here, and a symlink inside the workspace that
//! points elsewhere is still denied by the kernel.
//!
//! Fail closed: when `sandbox-exec` is missing (non-macOS, stripped system)
//! the tool refuses to run unless the caller explicitly set
//! [`ShellSandbox::allow_unsandboxed`]. `sandbox = false` on its own is not
//! enough either: it refuses too unless `allow_unsandboxed` is set as well.
//!
//! The child runs with `setsid()` (own session, no terminal), every inherited
//! descriptor >= 3 marked close-on-exec, and best-effort `RLIMIT_CPU` /
//! `RLIMIT_FSIZE` / `RLIMIT_NOFILE` caps. Output is captured to private files
//! in the temp dir, so a background process holding the stdout stream can
//! never turn a finished command into a timeout.

// The submodules are private on purpose: every public item is re-exported
// at this path, so `crate::sandbox::…` is exactly what it was before the
// split, and no new public path appears.
mod developer_dir;
mod error;
mod home;
mod launcher;
mod limits;
mod process;
mod profile;
mod sensitive;
mod shell;
mod stdio;
mod system;

#[cfg(test)]
mod tests;

pub use error::{launch_error, LaunchError};
pub use launcher::{launch, launch_with_limits, Launched};
pub use limits::{
    CPU_LIMIT_GRACE_SECS, DISABLED_MESSAGE, MAX_COMMAND_MEMORY_BYTES, MAX_EXTRA_PROCESSES,
    MAX_FILE_BYTES, MAX_OPEN_FILES, SANDBOX_EXEC, SANDBOX_PATH, UNAVAILABLE_MESSAGE,
};
pub use profile::seatbelt_profile;
pub use shell::ShellSandbox;
pub use stdio::StdioSandbox;
