//! Removal operations below the verified home.

use std::path::Path;

use super::SandboxHome;
#[cfg(unix)]
use crate::paths::scan::{fstatat_mode, mode_is_dir, read_dir_names};
#[cfg(unix)]
use crate::paths::sys::{fd_file_id, open_rel_dir_existing, openat_dir, unlinkat_flags, FileId};
use crate::paths::sys::{invalid_rel, relative_components};
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
    /// Before the up-walk re-walks the names from the tree root.
    UpWalk,
    /// Before an emptied directory is unlinked from its parent.
    BeforeUnlink,
}

/// Test hook run at each [`RaceStage`] on this thread; `true` means it
/// fired and is cleared.
#[cfg(all(test, unix))]
type RaceHook = Box<dyn FnMut(RaceStage) -> bool>;
#[cfg(all(test, unix))]
thread_local! {
    pub(in crate::paths) static RACE_HOOK: std::cell::RefCell<Option<RaceHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
fn race_seam(stage: RaceStage) {
    // Taken out first: the hook runs with the `RefCell` free.
    let Some(mut hook) = RACE_HOOK.take() else {
        return;
    };
    if !hook(stage) {
        RACE_HOOK.with(|slot| {
            slot.borrow_mut().get_or_insert(hook);
        });
    }
}

#[cfg(all(not(test), unix))]
fn race_seam(_stage: RaceStage) {}

impl SandboxHome {
    /// Remove the directory `rel` (must be empty); `false` when it, or a
    /// parent, does not exist. Nothing is created on the way.
    pub fn remove_dir(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            self.unlink_rel(rel, dirs, name, libc::AT_REMOVEDIR)
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
    /// fd (a linked ancestor or leaf is refused), a root on another device
    /// than its parent is refused, then the tree is deleted as `empty_tree`
    /// says. A missing `rel`, or a parent or tree directory that vanishes
    /// during the call, is `Ok`; nothing is created.
    ///
    /// A refusal mid-way (a link or another device swapped in, a changed
    /// directory) stops at once and leaves the tree partly emptied; no link
    /// is ever followed. Non-goals: the mount checks compare `st_dev` only
    /// (the root with its parent, each entered directory with the root), so
    /// a same-device bind mount passes and the home's own ancestors are not
    /// checked here. A same-uid process that moves a directory of the tree
    /// elsewhere during the call keeps it (it counts as removed), but while
    /// its fd is cached (the deepest `WINDOW` levels) its entries are still
    /// deleted at the new place; that uid could delete them itself.
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
            let parent_id = checked(rel, fd_file_id(&parent))?;
            if checked(rel, fd_file_id(&again))? != parent_id {
                return Err(refusal(rel, CHANGED));
            }
            drop(again);
            race_seam(RaceStage::AfterRecheck);
            let Some(tree) = found(rel, openat_dir(&parent, name, true))? else {
                return Ok(());
            };
            let dev = same_device(rel, parent_id, checked(rel, fd_file_id(&tree))?)?;
            empty_tree(rel, &tree, dev)?;
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

    /// Remove the file `rel`; `false` when it, or a parent, does not exist.
    /// Nothing is created on the way.
    pub fn remove_file(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            self.unlink_rel(rel, dirs, name, 0)
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

    /// `unlinkat(name, flags)` in the existing parent `dirs`, opened
    /// `O_NOFOLLOW` (a linked ancestor is refused as in `found`); a missing
    /// parent or entry is `Ok(false)`.
    #[cfg(unix)]
    fn unlink_rel(
        &self,
        rel: &Path,
        dirs: &[OsString],
        name: &OsStr,
        flags: libc::c_int,
    ) -> std::io::Result<bool> {
        let Some(dir) = found(rel, open_rel_dir_existing(self, dirs))? else {
            return Ok(false);
        };
        match unlinkat_flags(&dir, name, flags) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err),
        }
    }
}

/// French and English refusal reason, completed by the path.
#[cfg(unix)]
const CHANGED: (&str, &str) = (
    "a un dossier qui a changé pendant la suppression",
    "has a directory that changed during removal",
);

/// The identity of an opened directory; unreadable is a refusal.
#[cfg(unix)]
pub(in crate::paths) fn checked(rel: &Path, id: Option<FileId>) -> std::io::Result<FileId> {
    id.ok_or_else(|| {
        refusal(
            rel,
            (
                "a un dossier dont l'identité est illisible",
                "has a directory whose identity cannot be read",
            ),
        )
    })
}

/// The tree root's device; a root on another device than its parent (a
/// mount point) is refused before anything is emptied.
#[cfg(unix)]
pub(in crate::paths) fn same_device(
    rel: &Path,
    parent: FileId,
    root: FileId,
) -> std::io::Result<u64> {
    if root.dev != parent.dev {
        return Err(refusal(
            rel,
            ("est un point de montage", "is a mount point"),
        ));
    }
    Ok(root.dev)
}

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

/// Most parent fds the up-walk keeps open; with the walk's and the
/// caller's own, the peak is about 68 fds, well under the 256 soft limit
/// of macOS even with parallel callers.
#[cfg(unix)]
pub(in crate::paths) const WINDOW: usize = 64;

/// One entered directory: its name and identity, its parent's fd while in
/// the window, and its parent's names still to do.
#[cfg(unix)]
struct Level {
    name: OsString,
    id: FileId,
    parent: Option<OwnedFd>,
    rest: Vec<OsString>,
}

/// Delete every entry below `root` (on `dev`), fd-relative, with an
/// explicit stack: a directory is entered only via `openat(O_NOFOLLOW)`
/// on `dev` (a mount point is refused); anything else, a link included, is
/// unlinked as itself. The parent fds of the deepest `WINDOW` levels stay
/// open; above them the up-walk re-walks the names from `root` once per
/// window (`O(D·D/WINDOW)` opens, `O(D)` up to `WINDOW` levels), as
/// `reopen` says.
#[cfg(unix)]
fn empty_tree(rel: &Path, root: &OwnedFd, dev: u64) -> std::io::Result<()> {
    let mut stack: Vec<Level> = Vec::new();
    // Levels from `low` up hold their parent's fd.
    let mut low = 0;
    let mut dir = root.try_clone()?;
    let mut todo = read_dir_names(root)?;
    loop {
        if let Some(name) = todo.pop() {
            if let Some((child, id)) = unlink_or_enter(rel, &dir, &name, dev)? {
                let rest = std::mem::replace(&mut todo, read_dir_names(&child)?);
                let parent = Some(std::mem::replace(&mut dir, child));
                stack.push(Level {
                    name,
                    id,
                    parent,
                    rest,
                });
                if stack.len() - low > WINDOW {
                    stack[low].parent = None;
                    low += 1;
                }
            }
            continue;
        }
        // `dir` is empty: go back to its parent and remove it there.
        let Some(level) = stack.pop() else {
            return Ok(());
        };
        if let Some(parent) = level.parent {
            dir = parent;
        } else {
            let (parent, vanished, start) = reopen(rel, root, &mut stack)?;
            (dir, low) = (parent, start);
            if let Some(rest) = vanished {
                todo = rest;
                continue;
            }
        }
        todo = level.rest;
        race_seam(RaceStage::BeforeUnlink);
        // A link swapped in for the emptied directory is refused, never
        // followed nor removed.
        ignore_missing(unlinkat_flags(&dir, &level.name, libc::AT_REMOVEDIR))
            .map_err(|err| link_refusal(rel, err))?;
    }
}

/// Re-walk the names of `stack` from `root`, `O_NOFOLLOW`, refusing a
/// changed `(dev, ino)`, and keep the parent fds of its deepest `WINDOW`
/// levels; returns the top directory and the new window start. A directory
/// that vanished counts as removed: its level and those below it are
/// dropped, and its parent comes back with its names left to do.
#[cfg(unix)]
fn reopen(
    rel: &Path,
    root: &OwnedFd,
    stack: &mut Vec<Level>,
) -> std::io::Result<(OwnedFd, Option<Vec<OsString>>, usize)> {
    race_seam(RaceStage::UpWalk);
    let low = stack.len().saturating_sub(WINDOW);
    let mut dir = root.try_clone()?;
    for at in 0..stack.len() {
        let next = match openat_dir(&dir, &stack[at].name, true) {
            Ok(next) => next,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let rest = stack.drain(at..).next().map(|level| level.rest);
                return Ok((dir, rest, low.min(at)));
            }
            Err(err) => return Err(link_refusal(rel, err)),
        };
        if checked(rel, fd_file_id(&next))? != stack[at].id {
            return Err(refusal(rel, CHANGED));
        }
        if at >= low {
            stack[at].parent = Some(dir);
        }
        dir = next;
    }
    Ok((dir, None, low))
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
                let id = checked(rel, fd_file_id(&child))?;
                if id.dev != dev {
                    return Err(refusal(
                        rel,
                        ("contient un point de montage", "contains a mount point"),
                    ));
                }
                return Ok(Some((child, id)));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            // Swapped for a link or file since the stat: unlink it below.
            Err(err) if matches!(err.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) => {}
            Err(err) => return Err(err),
        }
    }
    ignore_missing(unlinkat_flags(dir, name, 0)).map(|()| None)
}
