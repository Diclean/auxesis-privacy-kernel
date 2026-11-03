//! Home-handle tests: creation, symlink swaps and the write gateway.

use super::*;
use crate::paths::*;

// --- Item 4: ensure_home / the write gateway --------------------------

#[test]
#[cfg(unix)]
fn ensure_home_refuses_a_symlink_into_the_real_auxesis() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    let real_aux = real_home.join(DEFAULT_DIR_NAME);
    std::fs::create_dir_all(&real_aux).unwrap();
    let sandbox_home = dir.path().join("sandbox-home");
    std::fs::create_dir_all(&sandbox_home).unwrap();
    let link = sandbox_home.join("home-link");
    std::os::unix::fs::symlink(&real_aux, &link).unwrap();

    let active = home_ctx(&real_home, true);
    let err = SandboxHome::open_with(&link, &active).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("refus de sandbox"), "{err}");

    // The same link is fine when the guard is not active.
    let inactive = home_ctx(&real_home, false);
    SandboxHome::open_with(&link, &inactive).unwrap();
}

#[test]
#[cfg(unix)]
fn ensure_home_refuses_a_dangling_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("dangling");
    std::os::unix::fs::symlink(dir.path().join("absent"), &link).unwrap();
    let ctx = home_ctx(dir.path(), true);
    let err = SandboxHome::open_with(&link, &ctx).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(
        !dir.path().join("absent").exists(),
        "no target may be created"
    );
}

#[test]
#[cfg(unix)]
fn ensure_home_allows_a_symlink_outside_the_real_home() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    let real_aux = real_home.join(DEFAULT_DIR_NAME);
    std::fs::create_dir_all(&real_aux).unwrap();
    let target = dir.path().join("sandbox-target");
    std::fs::create_dir_all(&target).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    SandboxHome::open_with(&link, &home_ctx(&real_home, true)).unwrap();
}

#[test]
#[cfg(unix)]
fn ensure_home_creates_the_directory_with_0700() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("nested").join("home");
    SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
    let mode = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "new homes are private");
    // Idempotent.
    SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
}

/// J02-2-BI2-01 (security review P1): a symlink swapped *after* `ensure_home` must
/// not redirect later writes — the handle holds the verified fd.
#[test]
#[cfg(unix)]
fn write_gateway_survives_a_home_symlink_swap() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let first = dir.path().join("first-target");
    let second = dir.path().join("second-target");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    let link = dir.path().join("home-link");
    std::os::unix::fs::symlink(&first, &link).unwrap();

    let handle = SandboxHome::open_with(&link, &home_ctx(&real_home, true)).unwrap();

    // The verified real path is the first target.
    let real = handle.real_path().unwrap();
    assert_eq!(
        std::fs::canonicalize(&real).unwrap(),
        std::fs::canonicalize(&first).unwrap()
    );

    // Swap the configured symlink to a second target after the check.
    // The handle's home is the CANONICAL path of the verified target, so
    // writes continue to land in the verified directory and the swapped
    // spelling is ignored (mid-run swaps are an explicit non-goal).
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&second, &link).unwrap();

    handle
        .write(Path::new("canary"), b"post-check", 0o600)
        .unwrap();
    assert!(handle.write_new(Path::new("new"), b"n", 0o600).unwrap());
    assert!(handle.real_path().is_ok());

    assert!(
        first.join("canary").is_file(),
        "the verified target keeps receiving writes"
    );
    assert!(first.join("new").is_file());
    assert!(
        !second.join("canary").exists(),
        "the swapped target must stay untouched"
    );
}

/// J-02 round 5 (security review P1): a pre-planted symlink in the sandbox home
/// (`whatsapp -> outside`, `voice -> outside`, any depth ≤ 2) is refused
/// at startup; production homes keep the historical tolerance.
#[test]
#[cfg(unix)]
fn guard_refuses_preplanted_symlinks_in_the_sandbox_home() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let home = dir.path().join("sandbox");
    std::fs::create_dir_all(&home).unwrap();

    let active = home_ctx(&real_home, true);
    for child in ["whatsapp", "voice"] {
        let link = home.join(child);
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let err = SandboxHome::open_with(&home, &active).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{child}");
        assert!(
            err.to_string().contains("lien symbolique"),
            "{child}: {err}"
        );
        std::fs::remove_file(&link).unwrap();
    }

    // Depth 2 (`agents/<name> -> outside`) is refused too.
    let agents = home.join("agents");
    std::fs::create_dir_all(&agents).unwrap();
    std::os::unix::fs::symlink(&outside, agents.join("main")).unwrap();
    assert!(SandboxHome::open_with(&home, &active).is_err());
    std::fs::remove_file(agents.join("main")).unwrap();

    // Depth 3 (`agents/<name>/workspace -> outside`, the engine agent
    // workspace) is refused as well (GLM F2).
    let agent_dir = agents.join("main");
    std::fs::create_dir_all(&agent_dir).unwrap();
    std::os::unix::fs::symlink(&outside, agent_dir.join("workspace")).unwrap();
    assert!(SandboxHome::open_with(&home, &active).is_err());

    // Production (inactive) keeps the historical tolerance: a symlink in
    // the real home is the owner's business.
    let inactive = home_ctx(&real_home, false);
    SandboxHome::open_with(&home, &inactive).unwrap();
}

#[test]
#[cfg(unix)]
fn write_gateway_refuses_parent_components() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
    assert!(
        handle.write(Path::new("../escape"), b"x", 0o600).is_err(),
        "a parent component must never escape the home"
    );
    assert!(handle.write(Path::new("/abs"), b"x", 0o600).is_err());
}
