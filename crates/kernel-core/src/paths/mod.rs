//! Filesystem layout of an Auxesis installation.
//!
//! Everything lives under the *Auxesis home*: `$AUXESIS_HOME` when set,
//! otherwise `$HOME/.auxesis`.
//!
//! # The sandbox guard (J-02)
//!
//! [`ensure_sandbox_guard`] is the single entry point every workspace binary
//! calls before it reads or creates anything. It resolves the real home from
//! the OS user database (`getpwuid_r`, never `$HOME`) and refuses an Auxesis
//! home that *is* or is *under* the real `~/.auxesis` — by **directory
//! identity** (`st_dev`, `st_ino`), not by path text, so case, NFD/NFC,
//! symlinks, firmlinks (`/System/Volumes/Data/…`), `/private/var` and
//! hardlinked spellings all resolve to the same inode and are refused. A
//! failed passwd lookup fails closed. `AUXESIS_HOME` equal to the real home
//! root is refused too.
//!
//! [`ensure_home`] then opens/creates the home through verified directory
//! descriptors and returns a [`SandboxHome`] handle. Every later write under
//! the sandbox home goes through that handle (`openat`/`O_NOFOLLOW` relative
//! to the verified fd), never through a path string, so a symlink swapped in
//! after the check cannot redirect a write (breaker round 2, security review P1).
//!
//! # Threat model (maintainer decision, 2026-10-06)
//!
//! In scope: **accidental use of the real `~/.auxesis`** — a binary or test
//! started with a misconfigured `HOME`/`AUXESIS_HOME`/port, or a sandbox home
//! that *resolves into* the real home at start, including via pre-planted
//! symlinks, firmlinks, case or NFD spellings. The guard verifies identity at
//! startup, exports the canonical verified path as the ONLY home consumers
//! use, and refuses a sandbox home containing any symlink (depth ≤ 2).
//!
//! Explicit non-goal: an attacker with same-user write access who **renames or
//! swaps directories while the process runs**. Such an attacker can already
//! edit `~/.auxesis` directly; the guard's job is not to defend against the
//! owner's own uid. Mid-run swap repros are documented, not chased; the
//! handle still re-verifies on every use where it can, which keeps the
//! daemon's state writes fail-closed in practice.

use std::path::{Path, PathBuf};

mod guard;
mod registry;
mod sandbox_home;
mod scan;
mod sys;

#[cfg(test)]
mod tests;

pub(crate) use guard::port_refusal;
pub use guard::real_user_home;
pub use registry::{
    ensure_home, verified_child_path, verified_home, verified_home_for, verified_home_or_verify,
};
pub use sandbox_home::SandboxHome;

use guard::{normalize_path, path_eq, SandboxContext};

/// Directory name used under `$HOME` by default.
pub const DEFAULT_DIR_NAME: &str = ".auxesis";

/// Environment variable that marks a sandboxed process (QA harnesses and
/// integration tests). When it is exactly `1`, Auxesis refuses to start
/// against the real `~/.auxesis` and refuses the real daemon port.
pub const SANDBOX_ENV: &str = "AUXESIS_SANDBOX";

/// Port the real daemon listens on by default (the daemon's `DEFAULT_API_PORT`).
///
/// Duplicated here so the sandbox guard can refuse it without `kernel-core`
/// depending on the daemon.
pub const REAL_DAEMON_PORT: u16 = 2893;

/// The one sandbox guard, called first by every workspace binary.
///
/// `api_port` is the port this process would bind (the daemon) or connect to
/// (clients); `None` when the binary never touches the daemon API. On
/// success the verified home to use is returned.
///
/// The guard is **active** when `AUXESIS_SANDBOX=1` is set, when `$HOME` is
/// unset/empty/relative or differs from the OS user database home, or when
/// the passwd lookup fails (fail closed). While active it refuses:
///
/// * any `AUXESIS_HOME` that *is* or is *under* the real `~/.auxesis`, by
///   directory identity (every spelling) and by a folded-path second check;
/// * `AUXESIS_HOME` equal to the real home root;
/// * a relative `AUXESIS_HOME`, or a missing one with no usable `$HOME`
///   (no silent CWD/real home fallback);
/// * the real daemon port [`REAL_DAEMON_PORT`] unless an explicit ephemeral
///   port (`AUXESIS_API_PORT=0`) is passed.
pub fn ensure_sandbox_guard(api_port: Option<u16>) -> Result<PathBuf, String> {
    let ctx = SandboxContext::resolve();
    let home = ctx.resolve_home()?;
    ctx.refuse_home(&home)?;
    if ctx.active && api_port == Some(REAL_DAEMON_PORT) {
        return Err(port_refusal());
    }
    // Export the canonical verified home as the ONE home for this process.
    // A read-only command (`aux activity`) must never create the home, so an
    // existing home is opened/registered/scanned while a missing one is only
    // canonicalised lexically.
    if !home.exists() {
        return Ok(normalize_path(&home));
    }
    let handle = ensure_home(&home).map_err(|err| err.to_string())?;
    // Export the canonical home to the process environment (production
    // binaries only; unit tests must not mutate global env under parallelism
    // — they read the registry instead).
    #[cfg(not(test))]
    if ctx.active {
        std::env::set_var("AUXESIS_HOME", handle.path());
    }
    Ok(handle.path().to_path_buf())
}

/// Whether the sandbox guard is active in this process (flag, `$HOME`
/// override, or a failed passwd lookup). Clients use this to decide whether
/// `--api`/`AUXESIS_API` may be trusted (J-02 round 3).
pub fn sandbox_guard_active() -> bool {
    SandboxContext::resolve().active
}

/// Compatibility wrapper: refuse `home` when it resolves into the real
/// `~/.auxesis` and the guard is active. Prefer [`ensure_sandbox_guard`].
pub fn ensure_sandbox_home(home: &Path) -> Result<(), String> {
    SandboxContext::resolve().refuse_home(home)
}

/// Connect/bind-time port check with the same active condition as
/// [`ensure_sandbox_guard`]: the real daemon port is refused while the guard
/// is active, whatever armed it.
pub fn ensure_sandbox_port(port: u16) -> Result<(), String> {
    if SandboxContext::resolve().active && port == REAL_DAEMON_PORT {
        return Err(port_refusal());
    }
    Ok(())
}

/// Resolve the Auxesis home directory.
///
/// `$AUXESIS_HOME` wins when set and non-blank (surrounding whitespace is
/// trimmed); otherwise `$HOME/.auxesis`. Binaries call
/// [`ensure_sandbox_guard`] first and use its return value; this helper stays
/// for library contexts that already run under the guard.
pub fn auxesis_home() -> PathBuf {
    let env_path = if let Ok(custom) = std::env::var("AUXESIS_HOME") {
        let custom = custom.trim();
        if !custom.is_empty() {
            PathBuf::from(custom)
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(DEFAULT_DIR_NAME)
        }
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(DEFAULT_DIR_NAME)
    };
    // One source of truth: when this env spelling belongs to a verified
    // home, return its canonical path (the exported home).
    if let Ok(handle) = verified_home() {
        if path_eq(handle.configured_path(), &env_path) || path_eq(handle.path(), &env_path) {
            return handle.path().to_path_buf();
        }
    }
    env_path
}

/// Route a write at `path` through the verified home gateway when the path
/// lives under the current Auxesis home; `None` when it does not (the caller
/// falls back to its legacy path-based behaviour). J-02 round 4: this lets
/// legacy private-file helpers (voice, WhatsApp) keep their API while the
/// home-derived path is resolved by the verified fd.
pub fn sandbox_write_path(path: &Path, data: &[u8], mode: u32) -> Option<std::io::Result<()>> {
    let home = auxesis_home();
    let rel = path.strip_prefix(&home).ok()?;
    let handle = match SandboxHome::open(&home) {
        Ok(handle) => handle,
        Err(err) => return Some(Err(err)),
    };
    Some(handle.write_atomic(rel, data, mode))
}

/// Path of the main configuration file.
pub fn config_path(home: &Path) -> PathBuf {
    home.join("config.toml")
}

/// Path of the SQLite store.
pub fn store_path(home: &Path) -> PathBuf {
    home.join("store.db")
}

/// Path of the log directory.
pub fn log_dir(home: &Path) -> PathBuf {
    home.join("logs")
}
