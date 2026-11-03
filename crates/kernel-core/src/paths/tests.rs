//! Unit tests for the path modules, grouped by responsibility.
//!
//! The suite is split only so every file stays under the size cap.

use std::path::Path;
use std::sync::Mutex;

use crate::paths::guard::SandboxContext;

/// Environment variables are process-global: serialize the tests that touch them.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Back to `$HOME` after an env-mutating test.
fn restore_home(previous: Option<String>) {
    match previous {
        Some(home) => std::env::set_var("HOME", home),
        None => std::env::remove_var("HOME"),
    }
}

/// The pure half of the guard for one explicit context.
fn check_sandbox_home(
    home: &Path,
    real_home: &Path,
    env_home: Option<&Path>,
    sandbox: bool,
) -> Result<(), String> {
    let ctx = SandboxContext::new(
        Some(real_home.to_path_buf()),
        env_home.map(Path::to_path_buf),
        sandbox,
    );
    ctx.refuse_home(home)
}

/// A context for the `ensure_home` tests: active unless explicitly
/// inactive with `HOME == real home`.
fn home_ctx(real_home: &Path, active: bool) -> SandboxContext {
    let env = if active {
        None
    } else {
        Some(real_home.to_path_buf())
    };
    SandboxContext::new(Some(real_home.to_path_buf()), env, active)
}

mod guard;
mod home;
mod read_dir;
mod scan;
