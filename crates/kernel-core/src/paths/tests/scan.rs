//! Startup scan tests: vanished entries, symlink swaps and errors.

use super::*;
use crate::paths::scan::{
    fstatat_mode, reject_symlinks_at_start, reject_symlinks_at_start_with, RealStartupScanFs,
    StartupScanFs,
};
use crate::paths::sys::openat_dir;
use crate::paths::*;

// --- FLAKY-03: the startup scan must tolerate a racing ENOENT ----------

/// Simulates SQLite unlinking `store.db-wal` between the scan's `readdir`
/// and its `fstatat`: the hook unlinks the real entry through the same
/// directory fd, so the following `fstatat` observes a genuine ENOENT.
#[cfg(unix)]
struct VanishingScanFs {
    victim: std::ffi::OsString,
}

#[cfg(unix)]
impl StartupScanFs for VanishingScanFs {
    fn read_dir_names(
        &self,
        dir: &std::os::fd::OwnedFd,
    ) -> std::io::Result<Vec<std::ffi::OsString>> {
        RealStartupScanFs.read_dir_names(dir)
    }

    fn fstatat_mode(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<u32> {
        if name == self.victim {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let c = std::ffi::CString::new(name.as_bytes()).unwrap();
            let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) };
            assert_eq!(rc, 0, "hook could not unlink {}", name.to_string_lossy());
        }
        fstatat_mode(dir, name)
    }

    fn open_child_dir(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
        nofollow: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        openat_dir(dir, name, nofollow)
    }
}

/// Test scanner that fails every `fstatat` with a chosen errno.
#[cfg(unix)]
struct FailingScanFs {
    errno: i32,
}

#[cfg(unix)]
impl StartupScanFs for FailingScanFs {
    fn read_dir_names(
        &self,
        dir: &std::os::fd::OwnedFd,
    ) -> std::io::Result<Vec<std::ffi::OsString>> {
        RealStartupScanFs.read_dir_names(dir)
    }

    fn fstatat_mode(
        &self,
        _dir: &std::os::fd::OwnedFd,
        _name: &std::ffi::OsStr,
    ) -> std::io::Result<u32> {
        Err(std::io::Error::from_raw_os_error(self.errno))
    }

    fn open_child_dir(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
        nofollow: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        openat_dir(dir, name, nofollow)
    }
}

/// Injected `openat` seam: at the child open, the victim directory is
/// removed and replaced with a symlink to `target` — the exact swap
/// window between `fstatat` and `openat(O_NOFOLLOW)`. The hook then calls
/// the real open and proves it returns ELOOP (Linux) or ENOTDIR (macOS).
#[cfg(unix)]
struct SwappedForSymlinkScanFs {
    victim: std::ffi::OsString,
    target: std::path::PathBuf,
}

#[cfg(unix)]
impl StartupScanFs for SwappedForSymlinkScanFs {
    fn read_dir_names(
        &self,
        dir: &std::os::fd::OwnedFd,
    ) -> std::io::Result<Vec<std::ffi::OsString>> {
        RealStartupScanFs.read_dir_names(dir)
    }

    fn fstatat_mode(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<u32> {
        fstatat_mode(dir, name)
    }

    fn open_child_dir(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
        nofollow: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        if name == self.victim {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let c = std::ffi::CString::new(name.as_bytes()).unwrap();
            let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) };
            assert_eq!(rc, 0, "hook could not rmdir {}", name.to_string_lossy());
            let target = std::ffi::CString::new(self.target.as_os_str().as_bytes()).unwrap();
            let rc = unsafe { libc::symlinkat(target.as_ptr(), dir.as_raw_fd(), c.as_ptr()) };
            assert_eq!(rc, 0, "hook could not symlinkat {}", name.to_string_lossy());
        }
        let result = openat_dir(dir, name, nofollow);
        if name == self.victim {
            let errno = result.as_ref().err().and_then(|e| e.raw_os_error());
            assert!(
                matches!(errno, Some(libc::ELOOP) | Some(libc::ENOTDIR)),
                "the swap must make the nofollow open fail with ELOOP/ENOTDIR, got {errno:?}"
            );
        }
        result
    }
}

/// Injected `openat` seam: at the child open, the victim directory is
/// removed so the real `openat` observes a genuine ENOENT.
#[cfg(unix)]
struct VanishingDirScanFs {
    victim: std::ffi::OsString,
}

#[cfg(unix)]
impl StartupScanFs for VanishingDirScanFs {
    fn read_dir_names(
        &self,
        dir: &std::os::fd::OwnedFd,
    ) -> std::io::Result<Vec<std::ffi::OsString>> {
        RealStartupScanFs.read_dir_names(dir)
    }

    fn fstatat_mode(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<u32> {
        fstatat_mode(dir, name)
    }

    fn open_child_dir(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
        nofollow: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        if name == self.victim {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let c = std::ffi::CString::new(name.as_bytes()).unwrap();
            let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) };
            assert_eq!(rc, 0, "hook could not rmdir {}", name.to_string_lossy());
        }
        openat_dir(dir, name, nofollow)
    }
}

/// Injected `openat` seam: the victim child open fails with a chosen errno.
#[cfg(unix)]
struct DeniedOpenScanFs {
    victim: std::ffi::OsString,
    errno: i32,
}

#[cfg(unix)]
impl StartupScanFs for DeniedOpenScanFs {
    fn read_dir_names(
        &self,
        dir: &std::os::fd::OwnedFd,
    ) -> std::io::Result<Vec<std::ffi::OsString>> {
        RealStartupScanFs.read_dir_names(dir)
    }

    fn fstatat_mode(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<u32> {
        fstatat_mode(dir, name)
    }

    fn open_child_dir(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
        nofollow: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        if name == self.victim {
            return Err(std::io::Error::from_raw_os_error(self.errno));
        }
        openat_dir(dir, name, nofollow)
    }
}

/// Records the entry names returned by every `read_dir_names` call so a
/// test can prove two consecutive scans of the same directory fd see the
/// same full entry set (the fresh-`.`-open vs `dup` offset guard).
#[cfg(unix)]
struct RecordingScanFs {
    seen: Mutex<Vec<Vec<std::ffi::OsString>>>,
}

#[cfg(unix)]
impl StartupScanFs for RecordingScanFs {
    fn read_dir_names(
        &self,
        dir: &std::os::fd::OwnedFd,
    ) -> std::io::Result<Vec<std::ffi::OsString>> {
        let names = RealStartupScanFs.read_dir_names(dir)?;
        self.seen.lock().unwrap().push(names.clone());
        Ok(names)
    }

    fn fstatat_mode(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<u32> {
        fstatat_mode(dir, name)
    }

    fn open_child_dir(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
        nofollow: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        openat_dir(dir, name, nofollow)
    }
}

/// (a) An entry that vanished between `readdir` and `fstatat` (ENOENT) is
/// skipped, not fatal: the FLAKY-03 SQLite WAL/SHM race.
#[test]
#[cfg(unix)]
fn startup_scan_skips_an_entry_that_vanishes_between_readdir_and_fstatat() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let sidecar = home.join("store.db-wal");
    std::fs::write(&sidecar, b"wal").unwrap();

    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
    let fs = VanishingScanFs {
        victim: std::ffi::OsString::from("store.db-wal"),
    };
    reject_symlinks_at_start_with(&handle.dir, 4, &["STOP", "api.token"], &fs).unwrap();
    assert!(!sidecar.exists(), "the hook removed the racing entry");
}

/// (b) A symlink in the home (at the root or nested inside the scanned
/// depth) still rejects startup exactly as before.
#[test]
#[cfg(unix)]
fn startup_scan_still_refuses_a_symlink_inside_the_home() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();

    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::os::unix::fs::symlink(&outside, home.join("whatsapp")).unwrap();
    let err = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("refus de sandbox"), "{err}");

    // Depth 4 covers agents/<agent>/workspace; recursion must still refuse.
    let nested_home = dir.path().join("nested-home");
    let deep = nested_home.join("agents").join("agent").join("workspace");
    std::fs::create_dir_all(&deep).unwrap();
    std::os::unix::fs::symlink(&outside, deep.join("leak")).unwrap();
    let err = SandboxHome::open_with(&nested_home, &home_ctx(&real_home, true)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("refus de sandbox"), "{err}");
}

/// (c) Only ENOENT is tolerated: permission-denied or any other stat
/// failure stays fatal.
#[test]
#[cfg(unix)]
fn startup_scan_keeps_non_enoent_errors_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("store.db"), b"db").unwrap();
    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

    let denied = FailingScanFs {
        errno: libc::EACCES,
    };
    let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &denied).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));

    let io = FailingScanFs { errno: libc::EIO };
    let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &io).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EIO));
}

/// (d) Real churn: one thread repeatedly creates/removes the SQLite
/// sidecars while the scan runs 2000 times; zero failures.
#[test]
#[cfg(unix)]
fn startup_scan_survives_store_sidecar_churn() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let churn = {
        let wal = home.join("store.db-wal");
        let shm = home.join("store.db-shm");
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = std::fs::write(&wal, b"wal");
                let _ = std::fs::write(&shm, b"shm");
                let _ = std::fs::remove_file(&wal);
                let _ = std::fs::remove_file(&shm);
            }
        })
    };

    for _ in 0..2000 {
        reject_symlinks_at_start(&handle.dir, 4, &["STOP", "api.token"]).unwrap();
    }

    stop.store(true, Ordering::Relaxed);
    churn.join().unwrap();
}

/// (e) security review P2: a child directory that `fstatat` saw as a directory but
/// that was replaced by a symlink before `openat(O_NOFOLLOW)` must make
/// the scan fail (ELOOP on Linux / ENOTDIR on macOS), never be swallowed.
#[test]
#[cfg(unix)]
fn startup_scan_fails_when_a_child_directory_becomes_a_symlink_before_open() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join("agents")).unwrap();
    std::fs::write(home.join("store.db"), b"db").unwrap();

    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
    let fs = SwappedForSymlinkScanFs {
        victim: std::ffi::OsString::from("agents"),
        target: outside.clone(),
    };
    let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("refus de sandbox"), "{err}");
    assert!(err.to_string().contains("agents"), "{err}");
}

/// (f) A directory that vanishes between `fstatat` and `openat` (ENOENT)
/// is skipped exactly like a vanished file: it cannot be the symlink we
/// refuse, and nothing was opened.
#[test]
#[cfg(unix)]
fn startup_scan_skips_a_directory_that_vanishes_between_fstatat_and_open() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    let victim = home.join("agents");
    std::fs::create_dir_all(&victim).unwrap();

    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
    let fs = VanishingDirScanFs {
        victim: std::ffi::OsString::from("agents"),
    };
    reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap();
    assert!(!victim.exists(), "the hook removed the racing directory");
}

/// (g) Any non-ENOENT child-open failure (EACCES here) is fatal, with the
/// entry named in the refusal.
#[test]
#[cfg(unix)]
fn startup_scan_keeps_a_denied_child_open_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join("agents")).unwrap();

    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
    let denied = DeniedOpenScanFs {
        victim: std::ffi::OsString::from("agents"),
        errno: libc::EACCES,
    };
    let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &denied).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("refus de sandbox"), "{err}");
    assert!(err.to_string().contains("agents"), "{err}");
}

/// (h) Deterministic guard for the fresh-`.`-open: two consecutive scans of
/// the same directory fd must both see every entry. If the scan `dup`-ed
/// the caller's fd, the second scan would inherit the drained offset and
/// read nothing.
#[test]
#[cfg(unix)]
fn startup_scan_sees_the_same_entries_on_two_consecutive_scans() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    for name in ["alpha", "beta", "gamma"] {
        std::fs::write(home.join(name), b"x").unwrap();
    }

    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
    let fs = RecordingScanFs {
        seen: Mutex::new(Vec::new()),
    };
    reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap();
    reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap();

    let seen = fs.seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "one read per scan on a leaf-only home");
    for names in seen.iter() {
        let mut got: Vec<String> = names
            .iter()
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()],
            "every scan must see the full entry set"
        );
    }
}

/// (i) The FLAKY-03 rule holds deeper in the tree too: an entry at depth 2
/// removed between `readdir` and `fstatat` is skipped, not fatal.
#[test]
#[cfg(unix)]
fn startup_scan_tolerates_a_vanishing_entry_at_depth_two() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    let agent = home.join("agents").join("agent");
    std::fs::create_dir_all(&agent).unwrap();
    let deep = agent.join("deep-wal");
    std::fs::write(&deep, b"wal").unwrap();

    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
    let fs = VanishingScanFs {
        victim: std::ffi::OsString::from("deep-wal"),
    };
    reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap();
    assert!(!deep.exists(), "the depth-2 entry was removed mid-scan");
}
