//! Directory-listing tests: readdir errors, errno and fd ownership.

use super::*;
use crate::paths::scan::{
    errno_location, fstatat_mode, read_dir_names, read_dir_names_with,
    reject_symlinks_at_start_with, DirReadFs, StartupScanFs,
};
use crate::paths::sys::openat_dir;
use crate::paths::*;

/// Scripted `readdir` step for [`ScriptedDirFs`].
#[cfg(unix)]
#[derive(Clone, Copy)]
enum ScriptStep {
    /// A successful `readdir`; it leaves the configured stale errno behind
    /// (POSIX allows a successful call to change errno).
    Entry(&'static str),
    /// A NULL `readdir` that leaves errno as-is: a clean end-of-directory.
    End,
    /// A NULL `readdir` that sets errno: a mid-listing I/O error.
    Error(libc::c_int),
}

/// Injected `readdir` seam: yields a scripted sequence of entries and then
/// either a clean end or a chosen OS error, and models a sticky errno so a
/// loop that fails to clear it per call observes a false error. Also counts
/// open/close so a double close (or a missed close) is visible.
#[cfg(unix)]
struct ScriptedDirFs {
    script: Vec<ScriptStep>,
    index: std::sync::atomic::AtomicUsize,
    stale_errno: libc::c_int,
    errno: std::sync::atomic::AtomicI32,
    opens: std::sync::atomic::AtomicUsize,
    closes: std::sync::atomic::AtomicUsize,
    live: std::sync::atomic::AtomicI32,
    double_close: std::sync::atomic::AtomicBool,
    fail_open_with: Option<libc::c_int>,
}

#[cfg(unix)]
impl ScriptedDirFs {
    fn new(script: Vec<ScriptStep>, stale_errno: libc::c_int) -> Self {
        Self {
            script,
            index: std::sync::atomic::AtomicUsize::new(0),
            stale_errno,
            errno: std::sync::atomic::AtomicI32::new(0),
            opens: std::sync::atomic::AtomicUsize::new(0),
            closes: std::sync::atomic::AtomicUsize::new(0),
            live: std::sync::atomic::AtomicI32::new(0),
            double_close: std::sync::atomic::AtomicBool::new(false),
            fail_open_with: None,
        }
    }

    fn fail_open_with(cursor_errno: libc::c_int) -> Self {
        let mut fs = Self::new(vec![ScriptStep::End], 0);
        fs.fail_open_with = Some(cursor_errno);
        fs
    }
}

#[cfg(unix)]
impl DirReadFs for ScriptedDirFs {
    type Cursor = ();

    fn open(&self, _dir: &std::os::fd::OwnedFd) -> std::io::Result<()> {
        use std::sync::atomic::Ordering;
        self.opens.fetch_add(1, Ordering::SeqCst);
        if let Some(errno) = self.fail_open_with {
            // Like `RealDirReadFs::open`: a failed open cleans up its own
            // fd, so the caller must not close anything.
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        self.index.store(0, Ordering::SeqCst);
        self.live.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn clear_errno(&self) {
        self.errno.store(0, std::sync::atomic::Ordering::SeqCst);
    }

    fn readdir(&self, _cursor: &()) -> Option<std::ffi::OsString> {
        use std::sync::atomic::Ordering;
        let step = *self.script.get(self.index.fetch_add(1, Ordering::SeqCst))?;
        match step {
            ScriptStep::Entry(name) => {
                self.errno.store(self.stale_errno, Ordering::SeqCst);
                Some(std::ffi::OsString::from(name))
            }
            ScriptStep::End => None,
            ScriptStep::Error(errno) => {
                self.errno.store(errno, Ordering::SeqCst);
                None
            }
        }
    }

    fn errno(&self) -> libc::c_int {
        self.errno.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn close(&self, _cursor: ()) {
        use std::sync::atomic::Ordering;
        self.closes.fetch_add(1, Ordering::SeqCst);
        if self.live.fetch_sub(1, Ordering::SeqCst) <= 0 {
            self.double_close.store(true, Ordering::SeqCst);
        }
    }
}

/// A `StartupScanFs` whose `read_dir_names` runs the real collection loop
/// over a scripted `DirReadFs`, so the whole scan path sees the injected
/// `readdir` fault. `fstatat`/`open_child_dir` stay real and are never
/// reached before the listing error.
#[cfg(unix)]
struct ScriptedScanFs {
    dir_fs: ScriptedDirFs,
}

#[cfg(unix)]
impl StartupScanFs for ScriptedScanFs {
    fn read_dir_names(
        &self,
        dir: &std::os::fd::OwnedFd,
    ) -> std::io::Result<Vec<std::ffi::OsString>> {
        read_dir_names_with(&self.dir_fs, dir)
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

/// (j) security review P2: a `readdir` I/O error *after* an ordinary entry must NOT
/// be reported as a clean (truncated) listing — the scan returns Err. On
/// the unfixed head, NULL is treated as end-of-directory and the scan
/// returns Ok with `["store.db"]`, never inspecting a later symlink.
#[test]
#[cfg(unix)]
fn startup_scan_returns_err_when_readdir_fails_after_an_entry() {
    use std::sync::atomic::Ordering;

    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join("agents")).unwrap();
    std::fs::write(home.join("store.db"), b"db").unwrap();
    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

    let fs = ScriptedScanFs {
        dir_fs: ScriptedDirFs::new(
            vec![ScriptStep::Entry("store.db"), ScriptStep::Error(libc::EIO)],
            0,
        ),
    };
    let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EIO),
        "the mid-listing I/O error must be fatal, not a truncated Ok: {err}"
    );
    assert_eq!(fs.dir_fs.opens.load(Ordering::SeqCst), 1);
    assert_eq!(fs.dir_fs.closes.load(Ordering::SeqCst), 1);
    assert_eq!(fs.dir_fs.live.load(Ordering::SeqCst), 0);
}

/// (k) security review P2: a `readdir` I/O error *before* the first entry is fatal
/// too (Err, not an empty Ok listing).
#[test]
#[cfg(unix)]
fn startup_scan_returns_err_when_readdir_fails_before_the_first_entry() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

    let fs = ScriptedScanFs {
        dir_fs: ScriptedDirFs::new(vec![ScriptStep::Error(libc::EIO)], 0),
    };
    let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EIO), "{err}");
}

/// (l) Stale errno must never be a false error: errno is cleared before
/// every `readdir`. A successful `readdir` leaves errno dirty and the
/// clean end-of-directory does not touch it, so only per-call clearing
/// keeps this listing Ok.
#[test]
#[cfg(unix)]
fn startup_scan_clears_errno_before_every_readdir() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

    // The scripted entry poisons errno with EIO; the clean NULL after it
    // must still be recognised as end-of-directory.
    let fs = ScriptedScanFs {
        dir_fs: ScriptedDirFs::new(
            vec![ScriptStep::Entry("store.db"), ScriptStep::End],
            libc::EIO,
        ),
    };
    reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs)
        .expect("a stale errno must not truncate or fail a clean listing");
}

/// (m) The real accessor path: errno set to EIO just before a genuine
/// listing of a real directory must not make the clean end a false error.
#[test]
#[cfg(unix)]
fn real_read_dir_names_ignores_a_stale_errno() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    for name in ["alpha", "beta", "gamma"] {
        std::fs::write(home.join(name), b"x").unwrap();
    }
    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

    // SAFETY: the pointer is this thread's errno storage.
    unsafe { *errno_location() = libc::EIO };
    let mut names = read_dir_names(&handle.dir).expect("stale errno is not a listing error");
    names.sort();
    assert_eq!(
        names,
        vec![
            std::ffi::OsString::from("alpha"),
            std::ffi::OsString::from("beta"),
            std::ffi::OsString::from("gamma"),
        ]
    );
}

/// (n) fd ownership: `fdopendir`/`closedir` close the stream exactly once
/// on the success and error paths, and an open failure never leaves a
/// close to the caller (no double close, no leak).
#[test]
#[cfg(unix)]
fn startup_scan_read_dir_closes_its_stream_exactly_once() {
    use std::sync::atomic::Ordering;

    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

    let assert_balanced = |fs: &ScriptedDirFs, opens: usize, closes: usize| {
        assert_eq!(fs.opens.load(Ordering::SeqCst), opens);
        assert_eq!(fs.closes.load(Ordering::SeqCst), closes);
        assert_eq!(fs.live.load(Ordering::SeqCst), 0, "no leaked/extra fd");
        assert!(
            !fs.double_close.load(Ordering::SeqCst),
            "the stream must never be closed twice"
        );
    };

    let clean = ScriptedDirFs::new(vec![ScriptStep::End], 0);
    read_dir_names_with(&clean, &handle.dir).unwrap();
    assert_balanced(&clean, 1, 1);

    let failing = ScriptedDirFs::new(vec![ScriptStep::Error(libc::EIO)], 0);
    assert!(read_dir_names_with(&failing, &handle.dir).is_err());
    assert_balanced(&failing, 1, 1);

    let denied = ScriptedDirFs::fail_open_with(libc::EACCES);
    let err = read_dir_names_with(&denied, &handle.dir).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
    assert_balanced(&denied, 1, 0);
}
