//! The launch path: the refusals, the private temp dir and the marker file.

use super::super::launcher::launch;
use super::super::limits::SANDBOX_EXEC;
use super::super::shell::ShellSandbox;
use super::super::LaunchError;
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
#[test]
fn launch_refuses_a_workspace_symlinked_to_the_root() {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("/", dir.path().join("root")).unwrap();

    let err = launch(
        "true",
        &dir.path().join("root"),
        &ShellSandbox {
            enabled: false,
            allow_unsandboxed: true,
            ..ShellSandbox::default()
        },
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert!(matches!(err, LaunchError::UnsafeWorkspace(_)));
}

#[cfg(target_os = "macos")]
#[test]
fn launch_refuses_a_sensitive_workspace() {
    // `/Library/Keychains` exists on every macOS host and is a protected
    // absolute location, so the launch path refuses it before spawning.
    let err = launch(
        "true",
        Path::new("/Library/Keychains"),
        &ShellSandbox::default(),
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert!(matches!(err, LaunchError::SensitiveWorkspace(_)), "{err}");
}

#[cfg(target_os = "macos")]
#[test]
fn launch_refuses_a_read_only_tree_workspace() {
    // WSD2-P2-04: `/usr` is read+exec only in the profile; as a workspace
    // it would become writable, so the launch path must refuse it.
    let err = launch(
        "true",
        Path::new("/usr"),
        &ShellSandbox::default(),
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert!(matches!(err, LaunchError::SensitiveWorkspace(_)), "{err}");
}

#[cfg(unix)]
#[test]
fn launch_keeps_a_read_only_marker_file() {
    let dir = tempfile::tempdir().unwrap();
    let launched = launch(
        "true",
        dir.path(),
        &ShellSandbox {
            enabled: false,
            allow_unsandboxed: true,
            ..ShellSandbox::default()
        },
        Duration::from_secs(60),
    )
    .unwrap();
    use std::os::unix::fs::MetadataExt;
    let metadata = launched.marker_file.metadata().unwrap();
    assert_eq!(metadata.len(), 0, "the marker file must stay empty");
    assert_eq!(metadata.nlink(), 0, "the marker file must be unlinked");
}

#[cfg(unix)]
#[test]
fn launch_creates_a_private_temp_dir() {
    // WSD3-P3-05: `tempfile` creates the dir with `create_dir` (0777 &
    // ~umask), so the launcher must tighten it to 0700 explicitly; the
    // documented "private temp dir" must not depend on the umask.
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let launched = launch(
        "true",
        dir.path(),
        &ShellSandbox {
            enabled: false,
            allow_unsandboxed: true,
            ..ShellSandbox::default()
        },
        Duration::from_secs(60),
    )
    .unwrap();
    let mode = std::fs::metadata(launched.temp.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700, "per-call temp dir must be 0700, got {mode:o}");
}

#[test]
fn production_profiles_always_run_the_fixed_helper() {
    // The helper is never configurable outside tests: every profile a
    // production caller can build runs through SANDBOX_EXEC.
    for sandbox in [
        ShellSandbox::default(),
        ShellSandbox::new(true, true, true),
        ShellSandbox::new(false, false, true),
    ] {
        assert_eq!(sandbox.sandbox_exec(), Path::new(SANDBOX_EXEC));
    }
}

#[test]
fn will_run_unsandboxed_mirrors_launch() {
    // The broker's unsandboxed bar must match what `launch` will do:
    // disabled-with-opt-in and unavailable-with-opt-in run unsandboxed;
    // everything else either sandboxes or refuses.
    let default = ShellSandbox::default();
    assert!(!default.will_run_unsandboxed(), "sandboxed by default");

    // Opted in while the sandbox is enabled: unsandboxed exactly when the
    // helper is unavailable (Linux, stripped macOS).
    let opted_in = ShellSandbox {
        allow_unsandboxed: true,
        ..ShellSandbox::default()
    };
    assert_eq!(opted_in.will_run_unsandboxed(), !opted_in.available());

    // Explicitly disabled with the opt-in: always unsandboxed.
    let disabled = ShellSandbox {
        enabled: false,
        allow_unsandboxed: true,
        ..ShellSandbox::default()
    };
    assert!(disabled.will_run_unsandboxed());

    // Disabled without the opt-in refuses to run at all — it must not be
    // reported as an unsandboxed run (the tool never executes).
    let refused = ShellSandbox {
        enabled: false,
        allow_unsandboxed: false,
        ..ShellSandbox::default()
    };
    assert!(!refused.will_run_unsandboxed());
}
