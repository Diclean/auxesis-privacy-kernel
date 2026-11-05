//! Removal operations below the verified home.

use std::path::Path;

use super::SandboxHome;
#[cfg(unix)]
use crate::paths::scan::{fstatat_mode, mode_is_dir, read_dir_names};
#[cfg(unix)]
use crate::paths::sys::{fd_file_id, open_rel_dir_existing, unlinkat_flags, FileId};
use crate::paths::sys::{invalid_rel, open_rel_dir, openat_dir, relative_components};
#[cfg(unix)]
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::os::fd::OwnedFd;

/// Points in [`SandboxHome::remove_dir_all`] where a test can act.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::paths) enum RaceStage {
    AfterOpen,
    AfterRecheck,
}

/// Test hook run at each [`RaceStage`] on this thread.
#[cfg(all(test, unix))]
type RaceHook = Box<dyn FnMut(RaceStage)>;
#[cfg(all(test, unix))]
thread_local! {
    pub(in crate::paths) static RACE_HOOK: std::cell::RefCell<Option<RaceHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
fn race_seam(stage: RaceStage) {
    RACE_HOOK.with(|slot| slot.borrow_mut().iter_mut().for_each(|hook| hook(stage)));
}

#[cfg(all(not(test), unix))]
fn race_seam(_stage: RaceStage) {}

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
    /// Every component is opened `O_NOFOLLOW | O_DIRECTORY` from the home
    /// fd (a linked ancestor or leaf is refused), then the tree is deleted
    /// as `empty_tree` says. A missing `rel`, or a parent that vanishes
    /// during the call, is `Ok`; nothing is created.
    pub fn remove_dir_all(&self, rel: &Path) -> std::io::Result<()> {
        self.reverify()?;
        let components = relative_components(rel)?;
        #[cfg(unix)]
        {
            let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
            let Some(parent) = found(rel, open_rel_dir_existing(self, dirs))? else {
                return Ok(());
            };
            race_seam(RaceStage::AfterOpen);
            // Re-walk the chain: an ancestor moved or linked since is refused.
            self.reverify()?;
            let Some(again) = found(rel, open_rel_dir_existing(self, dirs))? else {
                return Ok(());
            };
            if fd_file_id(&parent).is_none() || fd_file_id(&again) != fd_file_id(&parent) {
                return Err(refusal(rel, CHANGED));
            }
            race_seam(RaceStage::AfterRecheck);
            let Some(tree) = found(rel, openat_dir(&parent, name, true))? else {
                return Ok(());
            };
            empty_tree(rel, &tree)?;
            ignore_missing(unlinkat_flags(&parent, name, libc::AT_REMOVEDIR))
        }
        #[cfg(not(unix))]
        {
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

/// French and English refusal reason, completed by the path.
#[cfg(unix)]
const CHANGED: (&str, &str) = (
    "a un dossier qui a changé pendant la suppression",
    "has a directory that changed during removal",
);

#[cfg(unix)]
fn refusal(rel: &Path, (fr, en): (&str, &str)) -> std::io::Error {
    let rel = rel.display();
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("refus de sandbox : {rel} {fr}. / sandbox refused: {rel} {en}."),
    )
}

/// `ELOOP` (a link) or `ENOTDIR` (a file, or a link on macOS with
/// `O_DIRECTORY`) on the way to `rel` is a refusal; others pass through.
#[cfg(unix)]
pub(super) fn link_refusal(rel: &Path, err: std::io::Error) -> std::io::Error {
    match err.raw_os_error() {
        Some(libc::ELOOP) => refusal(
            rel,
            ("est ou traverse un lien", "is or goes through a link"),
        ),
        Some(libc::ENOTDIR) => refusal(
            rel,
            (
                "n'est pas un dossier ou traverse un lien ou un fichier",
                "is not a directory or goes through a link or a file",
            ),
        ),
        _ => err,
    }
}

/// The opened directory, `None` when missing; a link on the way is refused.
#[cfg(unix)]
fn found(rel: &Path, opened: std::io::Result<OwnedFd>) -> std::io::Result<Option<OwnedFd>> {
    match opened {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        other => other.map(Some).map_err(|err| link_refusal(rel, err)),
    }
}

#[cfg(unix)]
fn ignore_missing(result: std::io::Result<()>) -> std::io::Result<()> {
    match result {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Delete every entry below `root`, fd-relative, with an explicit stack: a
/// directory is entered only via `openat(O_NOFOLLOW)` (a mount point is
/// refused); anything else, a link included, is unlinked as itself. Only
/// two fds stay open, so depth is unbounded: going up re-walks the names
/// from `root`, `O_NOFOLLOW`, refusing a changed `(dev, ino)`.
#[cfg(unix)]
fn empty_tree(rel: &Path, root: &OwnedFd) -> std::io::Result<()> {
    let dev = fd_file_id(root)
        .ok_or_else(std::io::Error::last_os_error)?
        .dev;
    // Per level: name and identity of the entered dir, its parent's todo.
    let mut stack: Vec<(OsString, FileId, Vec<OsString>)> = Vec::new();
    let mut dir = root.try_clone()?;
    let mut todo = read_dir_names(root)?;
    loop {
        if let Some(name) = todo.pop() {
            if let Some((child, id)) = unlink_or_enter(rel, &dir, &name, dev)? {
                let rest = std::mem::replace(&mut todo, read_dir_names(&child)?);
                stack.push((name, id, rest));
                dir = child;
            }
            continue;
        }
        // `dir` is empty: go back to its parent and remove it there.
        let Some((name, _, rest)) = stack.pop() else {
            return Ok(());
        };
        dir = root.try_clone()?;
        for (step, id, _) in &stack {
            dir = openat_dir(&dir, step, true).map_err(|err| link_refusal(rel, err))?;
            if fd_file_id(&dir) != Some(*id) {
                return Err(refusal(rel, CHANGED));
            }
        }
        todo = rest;
        ignore_missing(unlinkat_flags(&dir, &name, libc::AT_REMOVEDIR))?;
    }
}

/// Unlink `name` in `dir`, or open it when it is a directory on `dev`.
#[cfg(unix)]
fn unlink_or_enter(
    rel: &Path,
    dir: &OwnedFd,
    name: &OsStr,
    dev: u64,
) -> std::io::Result<Option<(OwnedFd, FileId)>> {
    let mode = match fstatat_mode(dir, name) {
        Ok(mode) => mode,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    if mode_is_dir(mode) {
        match openat_dir(dir, name, true) {
            Ok(child) => {
                return match fd_file_id(&child) {
                    Some(id) if id.dev == dev => Ok(Some((child, id))),
                    _ => Err(refusal(
                        rel,
                        ("contient un point de montage", "contains a mount point"),
                    )),
                };
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            // Swapped for a link or file since the stat: unlink it below.
            Err(err) if matches!(err.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) => {}
            Err(err) => return Err(err),
        }
    }
    ignore_missing(unlinkat_flags(dir, name, 0)).map(|()| None)
}
