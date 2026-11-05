//! Anchored removal and `open_dir` tests: no link is followed on the way.

use super::*;
use crate::paths::*;

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

/// A symlink inside the tree is unlinked as a link; its target survives.
#[test]
#[cfg(unix)]
fn remove_dir_all_unlinks_inner_links_without_following_them() {
    let (dir, handle, outside) = tree_fixture();
    let pkg = dir.path().join("home/ext/pkg");
    std::os::unix::fs::symlink(outside.join("pkg"), pkg.join("dir-link")).unwrap();
    std::os::unix::fs::symlink(outside.join("pkg/keep"), pkg.join("sub/file-link")).unwrap();
    handle.remove_dir_all(Path::new("ext/pkg")).unwrap();
    assert!(!pkg.exists());
    assert_eq!(std::fs::read(outside.join("pkg/keep")).unwrap(), b"k");
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

    // Ancestor swapped for a link between the anchored open and the delete.
    let err = handle
        .remove_dir_all_with(Path::new("ext/pkg"), || {
            std::fs::rename(home.join("ext"), home.join("ext-old")).unwrap();
            std::os::unix::fs::symlink(&outside, home.join("ext")).unwrap();
        })
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert_eq!(std::fs::read(outside.join("pkg/keep")).unwrap(), b"k");
    assert!(home.join("ext-old/pkg/file").is_file(), "nothing removed");

    // Leaf swapped for a link at the same point.
    std::fs::remove_file(home.join("ext")).unwrap();
    std::fs::rename(home.join("ext-old"), home.join("ext")).unwrap();
    let err = handle
        .remove_dir_all_with(Path::new("ext/pkg"), || {
            std::fs::rename(home.join("ext/pkg"), home.join("ext/pkg-old")).unwrap();
            std::os::unix::fs::symlink(outside.join("pkg"), home.join("ext/pkg")).unwrap();
        })
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
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
    assert!(
        handle.open_dir(Path::new("link/pkg")).is_err(),
        "linked ancestor"
    );
    assert!(handle.open_dir(Path::new("link")).is_err(), "linked leaf");
    assert!(handle.open_dir(Path::new("ext/../link")).is_err());
    assert!(handle.open_dir(Path::new("..")).is_err());
    assert!(handle.open_dir(outside.as_path()).is_err(), "absolute");
    assert!(
        handle.open_dir(Path::new("ext/pkg/file")).is_err(),
        "a file"
    );
    assert_eq!(
        handle.open_dir(Path::new("missing")).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(!home.join("missing").exists(), "open_dir never creates");
}
