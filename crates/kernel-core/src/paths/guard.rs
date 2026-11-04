//! Sandbox guard context, identity checks, and refusal messages.
//!
//! The public guard entry points stay re-exported from `paths`.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use super::sys::{fd_file_id, fd_real_path, file_id, open_base_dir, openat_dir, FileId};
use super::{DEFAULT_DIR_NAME, REAL_DAEMON_PORT, SANDBOX_ENV};

/// Home directory the OS user database (`getpwuid_r(getuid())`) reports for
/// this process, never `$HOME`.
///
/// `$HOME` is exactly the variable a sandbox overrides, so it cannot be used
/// to recognise the real `~/.auxesis` (J-02). Returns `None` when the lookup
/// fails; non-unix platforms fall back to `$HOME`.
#[cfg(unix)]
pub fn real_user_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    let mut buf: Vec<libc::c_char> = vec![0; 1024];
    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `pwd` and `buf` outlive the call, which only writes into
        // them; `pw_dir` is read after a success return, while it still
        // points into `buf`.
        let rc = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
        return Some(PathBuf::from(OsStr::from_bytes(dir.to_bytes())));
    }
}

/// Non-unix fallback: there is no user database, so best effort via `$HOME`.
#[cfg(not(unix))]
pub fn real_user_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// The real home captured once per guard decision.
struct RealHome {
    path: PathBuf,
    id: Option<FileId>,
    aux_path: PathBuf,
    aux_id: Option<FileId>,
}

/// Resolved inputs of one guard decision.
pub(super) struct SandboxContext {
    real: Option<RealHome>,
    env_home: Option<PathBuf>,
    pub(super) active: bool,
}

impl SandboxContext {
    pub(super) fn resolve() -> Self {
        let sandbox = std::env::var(SANDBOX_ENV).ok().as_deref() == Some("1");
        let env_home = std::env::var_os("HOME").map(PathBuf::from);
        let lookup = lookup_real_home();
        Self::new(lookup, env_home, sandbox)
    }

    /// Pure constructor (unit tests): invalid/empty/relative `HOME` counts as
    /// overridden, never as a real home to compare against. A failed passwd
    /// lookup arms the guard and fails closed.
    pub(super) fn new(
        real_home: Option<PathBuf>,
        env_home: Option<PathBuf>,
        sandbox: bool,
    ) -> Self {
        let env_home = env_home.filter(|home| {
            let text = home.to_string_lossy();
            !text.trim().is_empty() && home.is_absolute()
        });
        let lookup_failed = real_home.is_none();
        let real = real_home.map(|path| {
            let id = file_id(&path);
            let aux_path = path.join(DEFAULT_DIR_NAME);
            let aux_id = file_id(&aux_path);
            RealHome {
                path,
                id,
                aux_path,
                aux_id,
            }
        });
        let active = sandbox
            || env_home.is_none()
            || lookup_failed
            || match (&env_home, &real) {
                (Some(env), Some(real)) => !path_eq(env, &real.path),
                _ => true,
            };
        Self {
            real,
            env_home,
            active,
        }
    }

    /// The home to use: `$AUXESIS_HOME` when set and non-blank, else
    /// `$HOME/.auxesis`. Never falls back to the CWD or the real home.
    pub(super) fn resolve_home(&self) -> Result<PathBuf, String> {
        self.resolve_home_from(std::env::var("AUXESIS_HOME").ok().as_deref())
    }

    pub(super) fn resolve_home_from(&self, auxesis_home: Option<&str>) -> Result<PathBuf, String> {
        if let Some(custom) = auxesis_home {
            let custom = custom.trim();
            if !custom.is_empty() {
                let home = PathBuf::from(custom);
                if self.active && !home.is_absolute() {
                    return Err(format!(
                        "refus de sandbox : AUXESIS_HOME doit être un chemin absolu (reçu {}) — pas de repli sur le répertoire courant. \
                         / sandbox refused: AUXESIS_HOME must be an absolute path (got {}) — refusing the CWD fallback.",
                        home.display(),
                        home.display()
                    ));
                }
                return Ok(home);
            }
        }
        if let Some(env_home) = &self.env_home {
            return Ok(env_home.join(DEFAULT_DIR_NAME));
        }
        Err("refus de sandbox : ni AUXESIS_HOME ni HOME absolu — aucun repli silencieux sur le répertoire courant. \
             / sandbox refused: neither AUXESIS_HOME nor an absolute HOME — refusing the silent CWD fallback."
            .to_string())
    }

    /// Refuse `home` when it *is* or is *under* the real `~/.auxesis`, or is
    /// the real home root itself.
    pub(super) fn refuse_home(&self, home: &Path) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        let Some(real) = &self.real else {
            return Err(fail_closed_refusal());
        };
        // Folded-path check first: it also covers a real `.auxesis` that does
        // not exist yet and non-unix platforms.
        if path_under(home, &real.aux_path) {
            return Err(home_refusal(home, &real.aux_path));
        }
        #[cfg(unix)]
        self.refuse_home_by_identity(home, real)?;
        Ok(())
    }

    /// Walk the candidate with `openat` from `/` and compare the identity of
    /// every existing component with the real `~/.auxesis` (and the final
    /// component with the real home). A not-yet-existing tail is checked
    /// against the deepest existing ancestor's resolved path.
    #[cfg(unix)]
    fn refuse_home_by_identity(&self, home: &Path, real: &RealHome) -> Result<(), String> {
        let mut dir = open_base_dir(home).map_err(|err| fail_closed_verify(&err))?;
        let components = path_components(home);
        let last = components.len().saturating_sub(1);
        let mut missing: Vec<OsString> = Vec::new();
        let mut resolved: Option<PathBuf> = None;
        for (index, name) in components.iter().enumerate() {
            let is_last = index == last;
            let fd = match openat_dir(&dir, name, true) {
                Ok(fd) => fd,
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                    missing.push(name.clone());
                    missing.extend(components.iter().skip(index + 1).cloned());
                    break;
                }
                Err(err)
                    if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) =>
                {
                    openat_dir(&dir, name, false).map_err(|err| fail_closed_verify(&err))?
                }
                Err(err) => return Err(fail_closed_verify(&err)),
            };
            if let Some(path) = check_fd(real, &fd, is_last, home)? {
                resolved = Some(path);
            }
            dir = fd;
        }
        if !missing.is_empty() {
            let base = resolved.unwrap_or_else(|| normalize_path(home));
            let candidate = missing.iter().fold(base, |acc, name| acc.join(name));
            if path_under(&candidate, &real.aux_path) {
                return Err(home_refusal(home, &real.aux_path));
            }
        }
        Ok(())
    }
}

/// Check one opened directory: refuse when its identity is the real
/// `~/.auxesis` (it is or is under it) or, as the final component, the real
/// home root; re-check the `F_GETPATH` spelling as a second layer.
#[cfg(unix)]
fn check_fd(
    real: &RealHome,
    fd: &std::os::fd::OwnedFd,
    is_last: bool,
    home: &Path,
) -> Result<Option<PathBuf>, String> {
    let id = fd_file_id(fd);
    if id.is_some() && id == real.aux_id {
        return Err(home_refusal(home, &real.aux_path));
    }
    if is_last && id.is_some() && id == real.id {
        return Err(home_refusal_root(home, &real.path));
    }
    let path = fd_real_path(fd);
    if let Some(path) = &path {
        if path_under(path, &real.aux_path) {
            return Err(home_refusal(home, &real.aux_path));
        }
    }
    Ok(path)
}

fn fail_closed_refusal() -> String {
    "refus de sandbox : le foyer réel de l'utilisateur est introuvable (getpwuid) — refus par précaution. \
     / sandbox refused: the OS user database lookup failed — failing closed."
        .to_string()
}

fn fail_closed_verify(err: &std::io::Error) -> String {
    format!(
        "refus de sandbox : impossible de vérifier le chemin ({err}) — refus par précaution. \
         / sandbox refused: cannot verify the path ({err}) — failing closed."
    )
}

/// Message for a home that resolves into the real `~/.auxesis`.
fn home_refusal(home: &Path, real_aux: &Path) -> String {
    let home = normalize_path(home);
    format!(
        "refus de sandbox : {SANDBOX_ENV}=1 ou HOME détourné, mais le foyer Auxesis résolu {} est sous le vrai {} — utilisez des chemins mktemp littéraux : `env -i HOME=<mktemp> AUXESIS_HOME=<mktemp>/{DEFAULT_DIR_NAME} {SANDBOX_ENV}=1 AUXESIS_API_PORT=0`. \
         / sandbox refused: the resolved Auxesis home {} is under the real {} — use literal mktemp paths.",
        home.display(),
        real_aux.display(),
        home.display(),
        real_aux.display()
    )
}

/// Message for `AUXESIS_HOME` equal to the real home root.
fn home_refusal_root(home: &Path, real_home: &Path) -> String {
    format!(
        "refus de sandbox : AUXESIS_HOME {} est le foyer réel lui-même — utilisez un sous-dossier mktemp. \
         / sandbox refused: AUXESIS_HOME is the real home root {} — use a literal mktemp subdirectory.",
        home.display(),
        real_home.display()
    )
}

/// Message for the real daemon port while the guard is active.
pub(crate) fn port_refusal() -> String {
    format!(
        "refus de sandbox : {SANDBOX_ENV}=1 ou HOME détourné, mais le port {REAL_DAEMON_PORT} est celui du vrai auxd — utilisez un port éphémère explicite (`AUXESIS_API_PORT=0`). \
         / sandbox refused: {SANDBOX_ENV}=1 or HOME overridden, but port {REAL_DAEMON_PORT} is the real auxd's — use an explicit ephemeral port (`AUXESIS_API_PORT=0`)."
    )
}

/// Case- and Unicode-normalisation-insensitive path key, used only as the
/// second (textual) check and for not-yet-existing tails. Identity is the
/// primary check.
fn path_key(path: &Path) -> Vec<String> {
    normalize_path(path)
        .components()
        .map(component_key)
        .collect()
}

fn component_key(component: Component<'_>) -> String {
    use unicode_normalization::UnicodeNormalization;
    component
        .as_os_str()
        .to_string_lossy()
        .nfd()
        .collect::<String>()
        .to_lowercase()
}

pub(super) fn path_eq(a: &Path, b: &Path) -> bool {
    path_key(a) == path_key(b)
}

fn path_under(candidate: &Path, base: &Path) -> bool {
    let candidate = path_key(candidate);
    let base = path_key(base);
    candidate.len() >= base.len() && candidate[..base.len()] == base[..]
}

/// Canonical path for comparison: canonicalise the longest existing ancestor
/// (resolving symlinks even when the leaf does not exist yet), append the
/// remaining components and fold `.`/`..` lexically. Dangling symlinks are
/// followed by hand — a symlink to the real home that does not exist yet must
/// not slip past. Falls back to pure lexical normalisation when nothing can
/// be resolved.
pub(super) fn normalize_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|dir| dir.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    resolve_symlinks(&absolute, 0).unwrap_or_else(|| lexical_normalize(&absolute))
}

/// Resolve `path` with `canonicalize`; when it does not exist, follow a
/// symlink component (dangling included) or recurse into the parent. Returns
/// `None` on an unreadable path or a symlink cycle (`depth` bounds the
/// recursion).
fn resolve_symlinks(path: &Path, depth: usize) -> Option<PathBuf> {
    const MAX_SYMLINK_DEPTH: usize = 40;
    if depth > MAX_SYMLINK_DEPTH {
        return None;
    }
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return Some(canonical);
    }
    if std::fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        let target = std::fs::read_link(path).ok()?;
        let target = if target.is_absolute() {
            target
        } else {
            path.parent()?.join(target)
        };
        return resolve_symlinks(&target, depth + 1);
    }
    let name = path.file_name()?;
    let parent = resolve_symlinks(path.parent()?, depth + 1)?;
    Some(parent.join(name))
}

/// Lexical `.`/`..` folding (used once every symlink is already resolved).
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Components of a candidate path for the `openat` walk (`..` is preserved
/// and resolved by the kernel).
pub(super) fn path_components(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect()
}

/// Verify an opened home directory while the guard is active: fail closed on
/// a failed lookup, refuse the real `~/.auxesis` identity (or an `F_GETPATH`
/// spelling under it) and the real home root as the final component.
#[cfg(unix)]
pub(super) fn verify_open_home_dir(
    dir: &std::os::fd::OwnedFd,
    ctx: &SandboxContext,
    is_last: bool,
    home: &Path,
) -> std::io::Result<()> {
    let Some(real) = &ctx.real else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            fail_closed_refusal(),
        ));
    };
    match check_fd(real, dir, is_last, home) {
        Ok(_) => Ok(()),
        Err(message) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            message,
        )),
    }
}

// Test hook: force the passwd lookup result (`Some(None)` = simulated
// failure) without touching the real user database.
//
// Thread-local on purpose: tests run in parallel threads within one binary,
// and a process-global override made every concurrently running test observe
// a failed `getpwuid` lookup and fail closed (e.g. the `config_lock` guard
// tests intermittently failing on a Linux build server with "foyer réel
// introuvable (getpwuid)"). Only the thread that installs the override is
// affected, and it is dropped with the thread even if the test panics.
#[cfg(test)]
thread_local! {
    pub(super) static FORCED_REAL_HOME: std::cell::RefCell<Option<Option<PathBuf>>> =
        const { std::cell::RefCell::new(None) };
}

fn lookup_real_home() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(forced) = FORCED_REAL_HOME.with(|slot| slot.borrow().clone()) {
        return forced;
    }
    real_user_home()
}
