//! Anchored removal and `open_dir` tests: no link is followed on the way.

use super::*;
use crate::paths::sandbox_home::{RaceStage, RACE_HOOK};
use crate::paths::*;
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
        if stage == at {
            std::fs::rename(&from, &old).unwrap();
            if let Some(to) = &to {
                std::os::unix::fs::symlink(to, &from).unwrap();
            }
        }
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
