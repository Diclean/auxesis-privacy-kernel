//! Exec rules: what may run, and what a copied binary may not.

#[cfg(target_os = "macos")]
use super::super::seatbelt_profile;
#[cfg(target_os = "macos")]
use super::platform::{assert_true_runs, run_under, temp_spec};

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_runs_a_plain_child_under_the_profile() {
    let (_root, spec) = temp_spec(&["/usr/bin/true", "/bin/echo"], None);
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);
    let out = run_under(&profile, "/bin/echo", &["hi"]);
    assert!(
        out.status.success() && out.stdout == b"hi\n",
        "/bin/echo must run: {:?} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_denies_exec_of_a_binary_copied_into_work() {
    let (_root, spec) = temp_spec(&["/usr/bin/true"], None);
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);

    let copy = spec.work_dir.join("truecopy");
    std::fs::copy("/usr/bin/true", &copy).expect("copy true");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let out = run_under(&profile, copy.to_str().expect("utf-8"), &[]);
    assert!(
        !out.status.success(),
        "a binary copied into work/ must not execute, got {:?}",
        out.status
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_denies_exec_of_curl() {
    // curl is not among the runtime interpreters.
    let (_root, spec) = temp_spec(&["/usr/bin/true"], None);
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);
    let out = run_under(&profile, "/usr/bin/curl", &["--version"]);
    assert!(
        !out.status.success(),
        "/usr/bin/curl must not execute, got {:?}",
        out.status
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_execs_a_shebang_script_only_through_its_exact_interpreter() {
    let (_root, spec) = temp_spec(&["/usr/bin/true", "/bin/cat"], None);
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);

    // /bin/cat is an allowed interpreter, so its script runs.
    let ok = spec.install_dir.join("runme");
    std::fs::write(&ok, b"#!/bin/cat\nhello\n").expect("write ok script");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o755)).expect("chmod ok");
    let out = run_under(&profile, ok.to_str().expect("utf-8"), &[]);
    assert!(
        out.status.success() && out.stdout == b"#!/bin/cat\nhello\n",
        "a script with an allowed interpreter must run: {:?} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    // The same script with a disallowed interpreter does not run, even
    // though the script file itself sits in the executable install dir.
    let blocked = spec.install_dir.join("blocked");
    std::fs::write(&blocked, b"#!/usr/bin/curl\nhello\n").expect("write blocked script");
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let out = run_under(&profile, blocked.to_str().expect("utf-8"), &[]);
    assert!(
        !out.status.success(),
        "a script with a disallowed interpreter must not run, got {:?}",
        out.status
    );
}
