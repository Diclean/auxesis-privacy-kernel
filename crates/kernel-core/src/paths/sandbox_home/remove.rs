//! Removal operations below the verified home.

use std::path::Path;

use super::SandboxHome;
#[cfg(unix)]
use crate::paths::scan::{fstatat_mode, mode_is_dir, read_dir_names};
#[cfg(unix)]
use crate::paths::sys::{fd_file_id, open_rel_dir_existing, unlinkat_flags};
use crate::paths::sys::{invalid_rel, open_rel_dir, openat_dir, relative_components};

/// Deepest tree [`SandboxHome::remove_dir_all`] descends; each level holds
/// one fd, so this also bounds the fds and stack in use.
#[cfg(unix)]
const MAX_REMOVE_DEPTH: usize = 64;

impl SandboxHome {
    /// Remove the directory `rel` (must be empty); `false` when it did not
    /// exist.
    pub fn remove_dir(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let dir = open_rel_dir(self, dirs)?;
            let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let rc =
                unsafe { libc::unlinkat(dir.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::NotFound {
                    return Ok(false);
                }
                return Err(err);
            }
            Ok(true)
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            match std::fs::remove_dir(path) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(err) => Err(err),
            }
        }
    }

    /// Recursively remove the directory `rel` without following any link.
    ///
    /// Every component is opened from the verified home fd with
    /// `O_NOFOLLOW | O_DIRECTORY`; a linked ancestor or leaf is refused.
    /// The subtree is then deleted fd-relative (`openat`/`unlinkat`): a link
    /// inside the tree is unlinked as a link, never followed, so swapping
    /// any component for a symlink mid-call cannot reach outside the home.
    /// A missing `rel` (or parent) is not an error and nothing is created.
    pub fn remove_dir_all(&self, rel: &Path) -> std::io::Result<()> {
        self.remove_dir_all_with(rel, || {})
    }

    /// [`SandboxHome::remove_dir_all`] with a seam run between the anchored
    /// open of the parent chain and the delete, so a test can swap a
    /// component for a link in that exact window.
    pub(in crate::paths) fn remove_dir_all_with(
        &self,
        rel: &Path,
        after_open: impl FnOnce(),
    ) -> std::io::Result<()> {
        self.reverify()?;
        let components = relative_components(rel)?;
        #[cfg(unix)]
        {
            let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
            let parent = match open_rel_dir_existing(self, dirs) {
                Ok(fd) => fd,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => return Err(link_refusal(rel, err)),
            };
            after_open();
            // Re-walk the chain: if any ancestor moved or became a link since
            // the open, refuse before deleting anything.
            self.reverify()?;
            let again = open_rel_dir_existing(self, dirs).map_err(|err| link_refusal(rel, err))?;
            let same = matches!(
                (fd_file_id(&again), fd_file_id(&parent)),
                (Some(now), Some(then)) if now == then
            );
            if !same {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "refus de sandbox : un dossier parent de {} a changé pendant la suppression. \
                         / sandbox refused: a parent of {} changed during removal.",
                        rel.display(),
                        rel.display()
                    ),
                ));
            }
            let tree = match openat_dir(&parent, name, true) {
                Ok(fd) => fd,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => return Err(link_refusal(rel, err)),
            };
            empty_tree(&tree, 0)?;
            drop(tree);
            unlinkat_flags(&parent, name, libc::AT_REMOVEDIR)
        }
        #[cfg(not(unix))]
        {
            after_open();
            let target = components
                .iter()
                .fold(self.home.clone(), |acc, part| acc.join(part));
            std::fs::remove_dir_all(target)
        }
    }

    /// Remove the file `rel`; `false` when it did not exist.
    pub fn remove_file(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;

        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let dir = open_rel_dir(self, dirs)?;
            let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::NotFound {
                    return Ok(false);
                }
                return Err(err);
            }
            Ok(true)
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            match std::fs::remove_file(path) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(err) => Err(err),
            }
        }
    }
}

/// A link (`ELOOP`, or `ENOTDIR` on macOS for `O_NOFOLLOW | O_DIRECTORY`)
/// on the way to `rel` becomes a sandbox refusal; other errors pass through.
#[cfg(unix)]
fn link_refusal(rel: &Path, err: std::io::Error) -> std::io::Error {
    if !matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) {
        return err;
    }
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "refus de sandbox : {} est ou traverse un lien symbolique. \
             / sandbox refused: {} is or goes through a symlink.",
            rel.display(),
            rel.display()
        ),
    )
}

/// Delete every entry below the open directory `dir`, fd-relative. A
/// directory is entered only through `openat(O_NOFOLLOW)`; anything else,
/// a symlink included, is unlinked as itself. An entry that vanishes
/// meanwhile is skipped.
#[cfg(unix)]
fn empty_tree(dir: &std::os::fd::OwnedFd, depth: usize) -> std::io::Result<()> {
    if depth >= MAX_REMOVE_DEPTH {
        return Err(std::io::Error::other("tree too deep to remove"));
    }
    for name in read_dir_names(dir)? {
        let mode = match fstatat_mode(dir, &name) {
            Ok(mode) => mode,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        let result = if mode_is_dir(mode) {
            match openat_dir(dir, &name, true) {
                Ok(child) => {
                    empty_tree(&child, depth + 1)?;
                    drop(child);
                    unlinkat_flags(dir, &name, libc::AT_REMOVEDIR)
                }
                // Swapped for a link (or file) since the stat: unlink the
                // entry itself, never what it points to.
                Err(err)
                    if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) =>
                {
                    unlinkat_flags(dir, &name, 0)
                }
                Err(err) => Err(err),
            }
        } else {
            unlinkat_flags(dir, &name, 0)
        };
        match result {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}
