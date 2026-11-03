//! Process-local registry of verified Auxesis homes.

use std::path::{Path, PathBuf};

use super::guard::{normalize_path, SandboxContext};
use super::sandbox_home::SandboxHome;

/// Create the home directory (and parents) if needed and return the verified
/// write handle.
///
/// Newly created homes are private (`0700`) on unix. On unix the walk opens
/// each component through `openat` with `O_NOFOLLOW` on the leaf, and while
/// the sandbox guard is active it re-verifies every opened directory by
/// identity and `F_GETPATH` (`/proc/self/fd` on Linux) so a symlink swapped
/// in after the check cannot redirect creation into the real `~/.auxesis`.
pub fn ensure_home(home: &Path) -> std::io::Result<SandboxHome> {
    let ctx = SandboxContext::resolve();
    let handle = SandboxHome::open_with(home, &ctx)?;
    register_verified_home(home, &handle);
    Ok(handle)
}

/// Register one verified home for `home` (keyed by its normalised path, so
/// several homes can coexist in one process — e.g. parallel tests).
fn register_verified_home(home: &Path, handle: &SandboxHome) {
    let key = normalize_path(home);
    if let Ok(mut homes) = VERIFIED_HOMES.lock() {
        homes.retain(|(existing, _)| *existing != key);
        homes.push((key, handle.clone()));
    }
}

/// The verified home for `home`, registering it when the process never ran
/// [`ensure_home`] (library/test callers). The home is always verified — a
/// raw path is never used.
pub fn verified_home_or_verify(home: &Path) -> std::io::Result<SandboxHome> {
    match verified_home_for(home) {
        Ok(handle) => Ok(handle),
        Err(_) => ensure_home(home),
    }
}

/// Canonical path of `rel` inside the verified home, for the rare APIs that
/// require a path (e.g. third-party readers). Built from the verified fd's
/// real path, never from the configured spelling.
pub fn verified_child_path(home: &Path, rel: &Path) -> std::io::Result<PathBuf> {
    Ok(verified_home_or_verify(home)?.real_path()?.join(rel))
}

/// The verified home handle registered for exactly this path.
///
/// Returns an error when [`ensure_home`] has not run for it: a consumer must
/// never fall back to a path string.
pub fn verified_home_for(home: &Path) -> std::io::Result<SandboxHome> {
    let key = normalize_path(home);
    let homes = VERIFIED_HOMES
        .lock()
        .map_err(|_| std::io::Error::other("verified home lock poisoned"))?;
    homes
        .iter()
        // The normalised key catches renamed spellings; the raw path catches
        // a path whose symlink target changed *after* registration (the
        // handle's own re-verification then refuses it).
        .find(|(existing, handle)| {
            *existing == key || handle.path() == home || handle.configured_path() == home
        })
        .map(|(_, handle)| handle.clone())
        .ok_or_else(|| std::io::Error::other("no verified home for this path"))
}

/// Verified homes registered by [`ensure_home`], keyed by their normalised
/// path. In a binary there is exactly one; tests may have several in flight
/// and each consumer asks for its own path via [`verified_home_for`].
static VERIFIED_HOMES: std::sync::Mutex<Vec<(PathBuf, SandboxHome)>> =
    std::sync::Mutex::new(Vec::new());

/// The most recently registered verified home (convenience for callers that
/// do not have a path); prefer [`verified_home_for`].
pub fn verified_home() -> std::io::Result<SandboxHome> {
    let homes = VERIFIED_HOMES
        .lock()
        .map_err(|_| std::io::Error::other("verified home lock poisoned"))?;
    homes
        .last()
        .map(|(_, handle)| handle.clone())
        .ok_or_else(|| std::io::Error::other("no verified home: ensure_home has not run"))
}
