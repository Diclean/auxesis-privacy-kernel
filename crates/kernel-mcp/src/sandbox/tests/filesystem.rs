//! Read and write rules: only the work dir is writable.

#[cfg(target_os = "macos")]
use super::super::seatbelt_profile;
#[cfg(target_os = "macos")]
use super::platform::{assert_true_runs, run_under, temp_spec};

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_denies_reads_and_stats_outside_the_allowed_paths() {
    let (_root, spec) = temp_spec(&["/usr/bin/true", "/bin/cat", "/usr/bin/stat"], None);
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);

    // A decoy in a temp HOME: not an ancestor of any allowed path, so its
    // metadata (and therefore stat) and its data are denied.
    let home = tempfile::tempdir().expect("decoy home");
    let decoy = home.path().join("decoy.txt");
    std::fs::write(&decoy, b"secret").expect("write decoy");

    let out = run_under(&profile, "/bin/cat", &[decoy.to_str().expect("utf-8")]);
    assert!(
        !out.status.success(),
        "reading a decoy outside the allowed paths must fail, got {:?}",
        out.status
    );
    let out = run_under(&profile, "/usr/bin/stat", &[decoy.to_str().expect("utf-8")]);
    assert!(
        !out.status.success(),
        "stat of a decoy in the temp HOME must fail, got {:?}",
        out.status
    );

    // Positive control: a file inside work/ is readable.
    let inside = spec.work_dir.join("ok.txt");
    std::fs::write(&inside, b"data").expect("write inside");
    let out = run_under(&profile, "/bin/cat", &[inside.to_str().expect("utf-8")]);
    assert!(
        out.status.success() && out.stdout == b"data",
        "reading work/ must succeed: {:?} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_denies_writes_outside_the_work_dir() {
    let (_root, spec) = temp_spec(&["/usr/bin/true", "/usr/bin/touch"], None);
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);

    let home = tempfile::tempdir().expect("decoy home");
    let outside = home.path().join("nope.txt");
    let out = run_under(
        &profile,
        "/usr/bin/touch",
        &[outside.to_str().expect("utf-8")],
    );
    assert!(
        !out.status.success(),
        "writing outside work/ must fail, got {:?}",
        out.status
    );

    // Positive control: writing inside work/ succeeds.
    let inside = spec.work_dir.join("made.txt");
    let out = run_under(
        &profile,
        "/usr/bin/touch",
        &[inside.to_str().expect("utf-8")],
    );
    assert!(
        out.status.success() && inside.exists(),
        "writing work/ must succeed: {:?} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}
