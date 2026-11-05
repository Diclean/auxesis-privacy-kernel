//! Verified handle on the Auxesis home, rooted at an open directory fd.
//!
//! Operation groups live in `read`, `remove`, and `write`.

use std::path::{Path, PathBuf};

use super::guard::{path_components, verify_open_home_dir, SandboxContext};
use super::scan::reject_symlinks_at_start;
use super::sys::{
    fchmod_0700, fd_file_id, fd_real_path, file_id, invalid_rel, mkdirat, open_base_dir,
    open_dir_by_path, open_rel_dir, openat_dir, relative_components, FileId,
};

mod read;
mod remove;
mod write;

#[cfg(all(test, unix))]
pub(in crate::paths) use remove::{RaceStage, RACE_HOOK};

// ---------------------------------------------------------------------------
// The write gateway: verified home handle
// ---------------------------------------------------------------------------

/// A verified handle on the Auxesis home.
///
/// [`crate::paths::ensure_home`] opens (creating when needed) the home
/// through `openat` with `O_NOFOLLOW` on every component and re-verifies it
/// against the real `~/.auxesis` identity. The handle keeps the directory fd
/// alive: every later write under the home goes through [`SandboxHome::write`]
/// and friends, which resolve relative to that fd — a symlink swapped in
/// after the check cannot redirect them.
pub struct SandboxHome {
    /// Canonical path of the verified directory (the ONLY home consumers
    /// use).
    home: PathBuf,
    /// The path as configured at registration (`AUXESIS_HOME`/`$HOME`), kept
    /// so `auxesis_home()` can recognise it.
    raw: PathBuf,
    #[cfg(unix)]
    pub(super) dir: std::os::fd::OwnedFd,
    #[cfg(unix)]
    id: FileId,
}

impl Clone for SandboxHome {
    fn clone(&self) -> Self {
        #[cfg(unix)]
        {
            Self {
                home: self.home.clone(),
                raw: self.raw.clone(),
                dir: self
                    .dir
                    .try_clone()
                    .expect("duplicating the verified home directory fd"),
                id: self.id,
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                home: self.home.clone(),
                raw: self.raw.clone(),
            }
        }
    }
}

impl std::fmt::Debug for SandboxHome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxHome")
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

impl SandboxHome {
    /// Open (creating when needed) `home`, verified against the real
    /// `~/.auxesis` while the guard is active.
    pub fn open(home: &Path) -> std::io::Result<Self> {
        let ctx = SandboxContext::resolve();
        Self::open_with(home, &ctx)
    }

    /// Like [`SandboxHome::open`] but never creates the home: a missing
    /// directory is `NotFound`.
    pub fn open_existing(home: &Path) -> std::io::Result<Self> {
        let ctx = SandboxContext::resolve();
        Self::open_existing_with(home, &ctx)
    }

    fn open_existing_with(home: &Path, ctx: &SandboxContext) -> std::io::Result<Self> {
        Self::finish_open(home, ctx, false)
    }

    pub(super) fn open_with(home: &Path, ctx: &SandboxContext) -> std::io::Result<Self> {
        Self::finish_open(home, ctx, true)
    }

    /// Canonicalise the verified directory once: `home` is the fd's real
    /// path (`F_GETPATH`/`/proc/self/fd`), exported as the ONLY home every
    /// consumer uses; `raw` keeps the configured spelling. While the guard
    /// is active the home is scanned (depth 2) for pre-planted symlinks.
    fn finish_open(home: &Path, ctx: &SandboxContext, create: bool) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            let dir = open_home_unix(home, ctx, create)?;
            let id = fd_file_id(&dir)
                .ok_or_else(|| std::io::Error::other("cannot fstat the verified home"))?;
            let canonical = fd_real_path(&dir)
                .ok_or_else(|| std::io::Error::other("cannot resolve the verified home"))?;
            if ctx.active {
                // Depth 4 covers agents/<agent>/workspace (GLM F2). The leaf
                // markers the guard itself manages (STOP, api.token) are
                // skipped: they have dedicated O_NOFOLLOW/identity handlers
                // and a dangling STOP must stay readable and resumable.
                reject_symlinks_at_start(&dir, 4, &["STOP", "api.token"])?;
            }
            Ok(Self {
                home: canonical,
                raw: home.to_path_buf(),
                dir,
                id,
            })
        }
        #[cfg(not(unix))]
        {
            if !home.exists() {
                if !create {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("{} does not exist", home.display()),
                    ));
                }
                std::fs::create_dir_all(home)?;
            }
            Ok(Self {
                home: home.to_path_buf(),
                raw: home.to_path_buf(),
            })
        }
    }

    /// Re-verify the held identity: open the home by path (leaf
    /// `O_NOFOLLOW`, ancestors resolved by the kernel) and compare its
    /// `(st_dev, st_ino)` with the held directory fd. Every mutating method
    /// calls this first, so a home renamed or swapped after the check is
    /// refused rather than followed.
    pub fn reverify(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            let fd = open_dir_by_path(&self.home)?;
            let now = fd_file_id(&fd)
                .ok_or_else(|| std::io::Error::other("cannot fstat the re-verified home"))?;
            if now != self.id {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "refus de sandbox : l'identité du foyer {} a changé depuis la vérification. \
                         / sandbox refused: the home identity changed since verification.",
                        self.home.display()
                    ),
                ));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    /// The directory's real path, obtained from the held fd (`F_GETPATH` on
    /// macOS, `/proc/self/fd` on Linux) after a re-verification. Consumers
    /// that must open by path (SQLite) build it from here, so it names the
    /// verified inode even when its configured path was renamed or swapped.
    pub fn real_path(&self) -> std::io::Result<PathBuf> {
        self.reverify()?;
        #[cfg(unix)]
        {
            fd_real_path(&self.dir).ok_or_else(|| {
                std::io::Error::other("cannot resolve the verified home's real path")
            })
        }
        #[cfg(not(unix))]
        {
            Ok(self.home.clone())
        }
    }

    /// After opening a file by path, prove the file at `opened` is the same
    /// inode as `rel` reachable through the verified directory fd.
    pub fn verify_file_inode(&self, rel: &Path, opened: &Path) -> std::io::Result<()> {
        self.reverify()?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let components = relative_components(rel)?;
            let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
            let dir = open_rel_dir(self, dirs)?;
            let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    name_c.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let via_fd = FileId {
                dev: stat.st_dev as u64,
                ino: stat.st_ino as u64,
            };
            let via_path = file_id(opened)
                .ok_or_else(|| std::io::Error::other("cannot stat the opened file"))?;
            if via_fd != via_path {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "refus de sandbox : {} n'est pas le fichier du foyer vérifié. \
                         / sandbox refused: {} is not the verified home's file.",
                        opened.display(),
                        opened.display()
                    ),
                ));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (rel, opened);
            Ok(())
        }
    }

    /// The canonical home path: the ONE path every consumer uses (exports,
    /// display, config/store paths).
    pub fn path(&self) -> &Path {
        &self.home
    }

    /// The path as configured at registration (used only to recognise the
    /// env spelling).
    pub fn configured_path(&self) -> &Path {
        &self.raw
    }
}

#[cfg(unix)]
fn open_home_unix(
    home: &Path,
    ctx: &SandboxContext,
    create: bool,
) -> std::io::Result<std::os::fd::OwnedFd> {
    let mut dir = open_base_dir(home)?;
    let components = path_components(home);
    let last = components.len().saturating_sub(1);
    let mut created = false;
    for (index, name) in components.iter().enumerate() {
        let is_last = index == last;
        dir = match openat_dir(&dir, name, true) {
            Ok(fd) => fd,
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                if !create {
                    return Err(err);
                }
                // Tolerate a concurrent creator winning the mkdir race.
                match mkdirat(&dir, name, 0o700) {
                    Ok(()) => {
                        if is_last {
                            created = true;
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(err) => return Err(err),
                }
                openat_dir(&dir, name, true)?
            }
            // A symlink component (`ELOOP`, or `ENOTDIR` on macOS where
            // `O_NOFOLLOW | O_DIRECTORY` reports a symlink that way): follow
            // it once; the verification below rejects a target under the
            // real ~/.auxesis. A regular file fails the retry with ENOTDIR.
            Err(err) if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
                openat_dir(&dir, name, false)?
            }
            Err(err) => return Err(err),
        };
        if ctx.active {
            verify_open_home_dir(&dir, ctx, is_last, home)?;
        }
    }
    if created {
        fchmod_0700(&dir)?;
    }
    Ok(dir)
}
