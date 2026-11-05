//! Anchored removal and `open_dir` tests: no link is followed on the way.

use super::*;
use crate::paths::sandbox_home::{checked, same_device, RaceStage, RACE_HOOK};
use crate::paths::sys::{mkdirat, openat_dir, FileId};
use crate::paths::*;
use std::ffi::OsStr;
use std::path::PathBuf;

/// A sandbox home with `ext/pkg/{file, sub/deep}` and an `outside` tree
/// holding a `pkg/keep` canary, opened through the guard.
#[cfg(unix)]
fn tree_fixture() -> (tempfile::TempDir, SandboxHome, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join("ext/pkg/sub")).unwrap();
    std::fs::write(home.join("ext/pkg/file"), b"f").unwrap();
    std::fs::write(home.join("ext/pkg/sub/deep"), b"d").unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(outside.join("pkg")).unwrap();
    std::fs::write(outside.join("pkg/keep"), b"k").unwrap();
    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
    (dir, handle, outside)
}

#[test]
#[cfg(unix)]
fn remove_dir_all_removes_a_normal_tree_and_tolerates_a_missing_one() {
    let (dir, handle, _outside) = tree_fixture();
    handle.remove_dir_all(Path::new("ext/pkg")).unwrap();
    assert!(!dir.path().join("home/ext/pkg").exists());
    assert!(dir.path().join("home/ext").is_dir(), "the parent stays");
    handle.remove_dir_all(Path::new("ext/pkg")).unwrap();
    handle.remove_dir_all(Path::new("absent/pkg")).unwrap();
    assert!(
        !dir.path().join("home/absent").exists(),
        "removal never creates a missing parent"
    );
    assert!(handle.remove_dir_all(Path::new("../outside")).is_err());
    assert!(handle.remove_dir_all(Path::new("/tmp")).is_err());
}

/// A linked ancestor or leaf is refused, before or during the call; the
/// outside tree survives every time.
#[test]
#[cfg(unix)]
fn remove_dir_all_refuses_a_linked_ancestor_or_leaf() {
    let (dir, handle, outside) = tree_fixture();
    let home = dir.path().join("home");

    // Ancestor already a link when the call starts.
    std::os::unix::fs::symlink(&outside, home.join("ext-link")).unwrap();
    let err = handle
        .remove_dir_all(Path::new("ext-link/pkg"))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    // Leaf already a link.
    std::os::unix::fs::symlink(outside.join("pkg"), home.join("ext/leaf-link")).unwrap();
    assert!(handle.remove_dir_all(Path::new("ext/leaf-link")).is_err());
    assert!(outside.join("pkg/keep").is_file());

    // Ancestor, then leaf, swapped for a link before the re-check: refused.
    for (from, target) in [("ext", outside.clone()), ("ext/pkg", outside.join("pkg"))] {
        race(RaceStage::AfterOpen, &home, from, Some(target));
        let err = handle.remove_dir_all(Path::new("ext/pkg")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert_eq!(std::fs::read(outside.join("pkg/keep")).unwrap(), b"k");
        std::fs::remove_file(home.join(from)).unwrap();
        std::fs::rename(home.join(format!("{from}-old")), home.join(from)).unwrap();
        assert!(home.join("ext/pkg/file").is_file(), "nothing removed");
    }

    // A parent that vanishes before the re-check: Ok, nothing removed.
    race(RaceStage::AfterOpen, &home, "ext", None);
    handle.remove_dir_all(Path::new("ext/pkg")).unwrap();
    assert!(home.join("ext-old/pkg/file").is_file());
    std::fs::rename(home.join("ext-old"), home.join("ext")).unwrap();

    // `ext` swapped after the re-check: the delete stays on the held fd.
    race(RaceStage::AfterRecheck, &home, "ext", Some(outside.clone()));
    handle.remove_dir_all(Path::new("ext/pkg")).unwrap();
    assert!(!home.join("ext-old/pkg").exists(), "the real tree is gone");
    assert_eq!(std::fs::read(outside.join("pkg/keep")).unwrap(), b"k");
}

/// Set this thread's race hook: at `at`, move `home/from` to `from-old`
/// and link it to `to`.
#[cfg(unix)]
fn race(at: RaceStage, home: &Path, from: &str, to: Option<PathBuf>) {
    let (from, old) = (home.join(from), home.join(format!("{from}-old")));
    RACE_HOOK.set(Some(Box::new(move |stage: RaceStage| {
        if stage != at {
            return false;
        }
        std::fs::rename(&from, &old).unwrap();
        if let Some(to) = &to {
            std::os::unix::fs::symlink(to, &from).unwrap();
        }
        true
    })));
}

/// A 300-deep tree is removed in full; links inside are unlinked, never
/// followed.
#[test]
#[cfg(unix)]
fn remove_dir_all_removes_a_300_deep_tree() {
    let (dir, handle, outside) = tree_fixture();
    let pkg = dir.path().join("home/ext/pkg");
    let deep = (0..300).fold(pkg.clone(), |acc, _| acc.join("d"));
    std::fs::create_dir_all(&deep).unwrap();
    std::os::unix::fs::symlink(outside.join("pkg"), deep.join("link")).unwrap();
    std::os::unix::fs::symlink(outside.join("pkg/keep"), pkg.join("sub/link")).unwrap();
    handle.remove_dir_all(Path::new("ext/pkg")).unwrap();
    assert!(!pkg.exists());
    assert_eq!(std::fs::read(outside.join("pkg/keep")).unwrap(), b"k");
}

/// A 2,000-deep tree (built fd-relative: its path is past `PATH_MAX`) goes
/// in full and fast, with one re-walk from the root per window of levels,
/// never one per level.
#[test]
#[cfg(unix)]
fn remove_dir_all_removes_a_2000_deep_tree_in_linear_time() {
    let (dir, handle, _outside) = tree_fixture();
    let pkg = dir.path().join("home/ext/pkg");
    let mut cur: std::os::fd::OwnedFd = std::fs::File::open(&pkg).unwrap().into();
    for _ in 0..2000 {
        mkdirat(&cur, OsStr::new("d"), 0o700).unwrap();
        cur = openat_dir(&cur, OsStr::new("d"), true).unwrap();
    }
    drop(cur);
    let walks = std::rc::Rc::new(std::cell::Cell::new(0_usize));
    let counter = walks.clone();
    RACE_HOOK.set(Some(Box::new(move |stage: RaceStage| {
        counter.set(counter.get() + usize::from(stage == RaceStage::UpWalk));
        false
    })));
    let started = std::time::Instant::now();
    handle.remove_dir_all(Path::new("ext/pkg")).unwrap();
    let took = started.elapsed();
    RACE_HOOK.set(None);
    assert!(!pkg.exists(), "the whole tree is gone");
    assert!(took < std::time::Duration::from_secs(20), "took {took:?}");
    assert!(walks.get() <= 2000 / 64 + 1, "{} re-walks", walks.get());
}

/// A directory of the tree that vanishes before the up-walk reaches it
/// counts as removed: the call is `Ok` and the rest of the tree still goes.
#[test]
#[cfg(unix)]
fn remove_dir_all_treats_a_dir_vanished_during_the_up_walk_as_removed() {
    let (dir, handle, _outside) = tree_fixture();
    let home = dir.path().join("home");
    let pkg = home.join("ext/pkg");
    std::fs::create_dir_all((0..200).fold(pkg.join("d"), |acc, _| acc.join("d"))).unwrap();
    let (from, to) = (pkg.join("d/d"), home.join("moved"));
    RACE_HOOK.set(Some(Box::new(move |stage: RaceStage| {
        stage == RaceStage::UpWalk && std::fs::rename(&from, &to).is_ok()
    })));
    handle.remove_dir_all(Path::new("ext/pkg")).unwrap();
    RACE_HOOK.set(None);
    assert!(!pkg.exists(), "the rest of the tree went");
    assert!(
        home.join("moved/d").is_dir(),
        "the moved dir is left as it is"
    );
}

/// The tree root on another device than its parent (a mount point) is
/// refused before anything is emptied; an unreadable identity has its own
/// reason, never "mount point".
#[test]
#[cfg(unix)]
fn a_mounted_root_and_an_unreadable_identity_are_refused_by_name() {
    let rel = Path::new("ext/pkg");
    let parent = FileId { dev: 1, ino: 2 };
    assert_eq!(
        same_device(rel, parent, FileId { dev: 1, ino: 3 }).unwrap(),
        1
    );
    let err = same_device(rel, parent, FileId { dev: 7, ino: 3 }).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert!(err.to_string().contains("is a mount point"), "{err}");
    assert!(err.to_string().contains("est un point de montage"), "{err}");
    let err = checked(rel, None).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert!(err.to_string().contains("identity cannot be read"), "{err}");
    assert!(!err.to_string().contains("mount"), "{err}");
    assert_eq!(checked(rel, Some(parent)).unwrap(), parent);
}

/// `remove_dir` and `remove_file` never create a missing parent: it is
/// `Ok(false)`, nothing to remove.
#[test]
#[cfg(unix)]
fn remove_dir_and_remove_file_never_create_a_missing_parent() {
    let (dir, handle, _outside) = tree_fixture();
    let home = dir.path().join("home");
    assert!(!handle.remove_file(Path::new("absent/deeper/file")).unwrap());
    assert!(!handle.remove_dir(Path::new("absent/deeper/dir")).unwrap());
    assert!(!home.join("absent").exists(), "nothing created");
    assert!(handle.remove_file(Path::new("ext/pkg/file")).unwrap());
    assert!(!handle.remove_file(Path::new("ext/pkg/file")).unwrap());
    assert!(
        handle.remove_dir(Path::new("ext/pkg/sub")).is_err(),
        "not empty"
    );
    assert!(handle.remove_file(Path::new("ext/pkg/sub/deep")).unwrap());
    assert!(handle.remove_dir(Path::new("ext/pkg/sub")).unwrap());
    assert!(!home.join("ext/pkg/sub").exists());
}

#[test]
#[cfg(unix)]
fn open_dir_is_anchored_on_every_component() {
    let (dir, handle, outside) = tree_fixture();
    let home = dir.path().join("home");
    let opened = handle.open_dir(Path::new("ext/pkg")).unwrap();
    assert!(opened.metadata().unwrap().is_dir());

    std::os::unix::fs::symlink(&outside, home.join("link")).unwrap();
    for (bad, says) in [
        ("link/pkg", "a link"),
        ("link", "a link"),
        ("ext/pkg/file/x", "a file"),
    ] {
        let err = handle.open_dir(Path::new(bad)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains(says), "{err}");
    }
    let err = handle
        .remove_dir_all(Path::new("ext/pkg/file/x"))
        .unwrap_err();
    assert!(err.to_string().contains("not a directory"), "{err}");
    assert!(handle.open_dir(Path::new("ext/../link")).is_err());
    assert!(handle.open_dir(Path::new("..")).is_err());
    assert!(handle.open_dir(outside.as_path()).is_err(), "absolute");
    assert_eq!(
        handle.open_dir(Path::new("missing")).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(!home.join("missing").exists(), "open_dir never creates");
}
