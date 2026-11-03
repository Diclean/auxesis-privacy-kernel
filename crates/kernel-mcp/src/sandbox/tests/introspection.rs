//! Process introspection, `dlopen` and the hardware identifiers.

#[cfg(target_os = "macos")]
use super::super::seatbelt_profile;
#[cfg(target_os = "macos")]
use super::platform::{
    assert_node_starts, assert_true_runs, compile_dylib, compile_probe, run_under, temp_spec,
};

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_denies_other_process_info() {
    let (_root, mut spec) = temp_spec(&["/usr/bin/true"], None);
    let probe = compile_probe(&spec.install_dir);
    spec.runtime_read_paths.push(probe.clone());
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);

    // A same-uid decoy with a marker in its environment. Only denial is
    // asserted; the marker is never read or printed.
    let mut decoy = std::process::Command::new("/bin/sleep")
        .arg("120")
        .env("AUX_DECOY_TOKEN", "decoy-round2-not-a-secret")
        .spawn()
        .expect("spawn decoy");
    let pid = decoy.id().to_string();
    let probe = probe.to_str().expect("utf-8");

    let args = run_under(&profile, probe, &["args", &pid]);
    assert!(
        args.status.success() && String::from_utf8_lossy(&args.stdout).starts_with("ARGS_DENIED"),
        "KERN_PROCARGS2 on another process must be denied: {:?} {}",
        args.status,
        String::from_utf8_lossy(&args.stdout)
    );
    let path = run_under(&profile, probe, &["path", &pid]);
    assert!(
        path.status.success() && String::from_utf8_lossy(&path.stdout).starts_with("PATH_DENIED"),
        "proc_pidpath on another process must be denied: {:?} {}",
        path.status,
        String::from_utf8_lossy(&path.stdout)
    );

    let _ = decoy.kill();
    let _ = decoy.wait();
    assert_node_starts();
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_denies_dlopen_of_a_dylib_in_work() {
    let (_root, mut spec) = temp_spec(&["/usr/bin/true"], None);
    let probe = compile_probe(&spec.install_dir);
    spec.runtime_read_paths.push(probe.clone());
    // The install-dir copy is the positive control; the work/ copy is the
    // one the file-map-executable deny must block.
    let install_dylib = compile_dylib(&spec.install_dir, "libprobe.dylib");
    let work_dylib = spec.work_dir.join("libprobe.dylib");
    std::fs::copy(&install_dylib, &work_dylib).expect("copy dylib into work");
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);
    let probe = probe.to_str().expect("utf-8");

    let ok = run_under(
        &profile,
        probe,
        &["dlopen", install_dylib.to_str().expect("utf-8")],
    );
    assert!(
        ok.status.success() && ok.stdout == b"DLOPEN_OK\n",
        "dlopen from the install dir must work: {:?} {}",
        ok.status,
        String::from_utf8_lossy(&ok.stdout)
    );
    let denied = run_under(
        &profile,
        probe,
        &["dlopen", work_dylib.to_str().expect("utf-8")],
    );
    assert!(
        denied.status.success() && denied.stdout == b"DLOPEN_FAIL\n",
        "dlopen from work/ must be denied: {:?} {}",
        denied.status,
        String::from_utf8_lossy(&denied.stdout)
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_denies_iokit_platform_serial() {
    let (_root, mut spec) = temp_spec(&["/usr/bin/true"], None);
    let probe = compile_probe(&spec.install_dir);
    spec.runtime_read_paths.push(probe.clone());
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);

    let out = run_under(&profile, probe.to_str().expect("utf-8"), &["serial"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.starts_with("SERIAL_DENIED"),
        "the platform serial must be unreadable: {:?} {stdout}",
        out.status
    );
    // The probe prints only the denial shape, never a serial value.
    assert!(!stdout.contains("SERIAL_OK"), "{stdout}");
    assert_node_starts();
}
