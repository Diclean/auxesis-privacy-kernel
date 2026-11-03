//! Startup symlink scan plus the fd-relative directory-listing loop.

use super::sys::openat_dir;

/// The two syscalls the startup symlink scan depends on. Kept behind this
/// seam so a unit test can deterministically make one entry vanish between
/// `readdir` and `fstatat` (or fail the stat), without races.
#[cfg(unix)]
pub(super) trait StartupScanFs {
    fn read_dir_names(
        &self,
        dir: &std::os::fd::OwnedFd,
    ) -> std::io::Result<Vec<std::ffi::OsString>>;
    fn fstatat_mode(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<u32>;
    /// Open a child directory without following a symlink. Kept behind the
    /// same seam so a test can swap a directory for a symlink in the exact
    /// window between `fstatat` and this open (or fail the open with a chosen
    /// errno) without a real race.
    fn open_child_dir(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
        nofollow: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd>;
}

/// The real syscalls; every production scan uses this.
#[cfg(unix)]
pub(super) struct RealStartupScanFs;

#[cfg(unix)]
impl StartupScanFs for RealStartupScanFs {
    fn read_dir_names(
        &self,
        dir: &std::os::fd::OwnedFd,
    ) -> std::io::Result<Vec<std::ffi::OsString>> {
        read_dir_names(dir)
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

/// Refuse a sandbox home that contains a symlink at depth ≤ `depth`
/// (J-02 round 5): sandbox homes are fresh temp directories and never need
/// one, and a pre-planted `<home>/whatsapp -> outside` must not redirect
/// session/audit/voice reads or writes.
///
/// FLAKY-03: an entry that disappears between `readdir` and `fstatat`
/// (ENOENT) is skipped, not fatal. Another `aux` process closing the SQLite
/// store unlinks `store.db-wal`/`store.db-shm` exactly while the daemon scans, and
/// a name that no longer exists cannot be the symlink we would follow. Every
/// other stat error stays fatal. The check order remains secure: entries are
/// stat'ed with `fstatat(AT_SYMLINK_NOFOLLOW)` relative to the opened
/// directory fd (never a path-based `lstat` after a join), recursion happens
/// only through `openat(O_NOFOLLOW)`, and nothing is later opened from a path
/// built here — every read/write under the home goes through the same verified
/// handle with `O_NOFOLLOW` and identity re-verification, so an entry swapped
/// for a symlink after this stat is refused, not followed.
#[cfg(unix)]
pub(super) fn reject_symlinks_at_start(
    dir: &std::os::fd::OwnedFd,
    depth: u32,
    skip: &[&str],
) -> std::io::Result<()> {
    reject_symlinks_at_start_with(dir, depth, skip, &RealStartupScanFs)
}

#[cfg(unix)]
pub(super) fn reject_symlinks_at_start_with(
    dir: &std::os::fd::OwnedFd,
    depth: u32,
    skip: &[&str],
    fs: &dyn StartupScanFs,
) -> std::io::Result<()> {
    if depth == 0 {
        return Ok(());
    }
    for name in fs.read_dir_names(dir)? {
        if skip.iter().any(|managed| name == *managed) {
            continue;
        }
        let mode = match fs.fstatat_mode(dir, &name) {
            Ok(mode) => mode,
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                // The entry vanished between readdir and fstatat: skip it. It
                // no longer exists, so it cannot be the symlink we refuse, and
                // no later open is derived from this stat.
                continue;
            }
            Err(err) => return Err(err),
        };
        if mode_is_symlink(mode) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refus de sandbox : le foyer vérifié contient un lien symbolique ({}) — les foyers sandbox sont des dossiers mktemp sans lien. \
                     / sandbox refused: the verified home contains a symlink ({}) — sandbox homes are fresh mktemp directories and never need one.",
                    name.to_string_lossy(),
                    name.to_string_lossy()
                ),
            ));
        }
        if mode_is_dir(mode) {
            match fs.open_child_dir(dir, &name, true) {
                Ok(child) => {
                    reject_symlinks_at_start_with(&child, depth - 1, &[], fs)?;
                }
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                    // The directory disappeared between fstatat and openat
                    // (a concurrent cleanup): skip it, the same rule as the
                    // fstatat ENOENT above. Nothing was opened, so there is
                    // no child to recurse into.
                }
                Err(err) => return Err(scan_open_refusal(&name, &err)),
            }
        }
    }
    Ok(())
}

/// A fatal `openat(O_NOFOLLOW)` failure during the startup symlink scan:
/// same error shape and bilingual style as a found symlink, naming only the
/// entry and never a joined path. The entry was a directory at `fstatat`
/// time but could not be opened without following a link — ELOOP/ENOTDIR
/// means a symlink took its place in that window, exactly the swap this scan
/// refuses; any other errno (EACCES, EMFILE, ...) must fail closed too.
#[cfg(unix)]
fn scan_open_refusal(name: &std::ffi::OsStr, err: &std::io::Error) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "refus de sandbox : l'entrée vérifiée d'un dossier n'a pas pu être ouverte sans suivre de lien ({0} — {1}) — un dossier a pu être remplacé par un lien symbolique après la vérification. \
             / sandbox refused: the verified entry of a directory could not be opened without following a link ({0}) — a directory may have been swapped for a symlink after the check.",
            name.to_string_lossy(),
            err
        ),
    )
}

/// This thread's errno storage, per platform.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(super) fn errno_location() -> *mut libc::c_int {
    // SAFETY: `__error` returns this thread's errno storage.
    unsafe { libc::__error() }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn errno_location() -> *mut libc::c_int {
    // SAFETY: `__errno_location` returns this thread's errno storage.
    unsafe { libc::__errno_location() }
}

/// Other unix libcs (BSD) expose the same accessor as macOS.
#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android"
    ))
))]
pub(super) fn errno_location() -> *mut libc::c_int {
    // SAFETY: BSD libc exposes `__error` for this thread's errno.
    unsafe { libc::__error() }
}

/// Set this thread's errno to 0 before a `readdir` call, so a following NULL
/// can be disambiguated: NULL means end-of-directory only when errno is 0.
#[cfg(unix)]
fn clear_process_errno() {
    // SAFETY: the pointer is this thread's errno storage.
    unsafe { *errno_location() = 0 };
}

/// This thread's errno after the most recent syscall.
#[cfg(unix)]
fn process_errno() -> libc::c_int {
    // SAFETY: the pointer is this thread's errno storage.
    unsafe { *errno_location() }
}

/// The directory-listing syscalls behind one open stream. Kept behind this
/// seam so a unit test can deterministically make a mid-listing `readdir` fail
/// with a chosen errno (EIO) and can count fd opens/closes, without any
/// production-reachable injection switch. Every production scan uses
/// [`RealDirReadFs`].
#[cfg(unix)]
pub(super) trait DirReadFs {
    /// Cursor over one open listing; owns the fd `fdopendir` took over.
    type Cursor;

    /// Open a fresh file description for "." under `dir` and `fdopendir` it.
    /// On failure the opened fd is closed exactly once and the *original* OS
    /// error is returned, never one clobbered by the close.
    fn open(&self, dir: &std::os::fd::OwnedFd) -> std::io::Result<Self::Cursor>;

    /// Clear this thread's errno before the next `readdir`.
    fn clear_errno(&self);

    /// One `readdir`: `Some(name)` when the pointer is non-NULL, `None` when
    /// it is NULL (end-of-directory or error — the caller checks `errno`).
    fn readdir(&self, cursor: &Self::Cursor) -> Option<std::ffi::OsString>;

    /// The errno left by the last `readdir`.
    fn errno(&self) -> libc::c_int;

    /// Close the listing exactly once.
    fn close(&self, cursor: Self::Cursor);
}

/// One open `DIR*` stream; owns the fd `fdopendir` took over.
#[cfg(unix)]
struct RealDirCursor {
    stream: *mut libc::DIR,
}

/// The real syscalls; every production scan uses this.
#[cfg(unix)]
struct RealDirReadFs;

#[cfg(unix)]
impl DirReadFs for RealDirReadFs {
    type Cursor = RealDirCursor;

    fn open(&self, dir: &std::os::fd::OwnedFd) -> std::io::Result<RealDirCursor> {
        use std::os::fd::AsRawFd;
        // Open a fresh file description for "." instead of `dup`-ing the
        // caller's fd: `dup` shares the directory offset, so a second scan on
        // the same fd would silently read nothing. `openat` gives an
        // independent offset and a relative "." can never be a symlink out of
        // this directory.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            // Capture the fdopendir error BEFORE `close`: `close` sets its own
            // errno and would otherwise clobber this diagnostic.
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        Ok(RealDirCursor { stream })
    }

    fn clear_errno(&self) {
        clear_process_errno();
    }

    fn readdir(&self, cursor: &RealDirCursor) -> Option<std::ffi::OsString> {
        use std::ffi::{CStr, OsStr};
        use std::os::unix::ffi::OsStrExt;
        let entry = unsafe { libc::readdir(cursor.stream) };
        if entry.is_null() {
            return None;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        Some(OsStr::from_bytes(name.to_bytes()).to_os_string())
    }

    fn errno(&self) -> libc::c_int {
        process_errno()
    }

    fn close(&self, cursor: RealDirCursor) {
        unsafe { libc::closedir(cursor.stream) };
    }
}

/// Collect the entries of one open cursor, excluding `.`/`..`.
///
/// Security review P2: errno is cleared before EVERY `readdir`, so a stale value from an
/// earlier syscall can never turn a clean end-of-directory into a false
/// truncation; conversely a NULL result with a non-zero errno is a fatal OS
/// error, never a silently truncated listing.
#[cfg(unix)]
fn collect_dir_names<F: DirReadFs>(
    fs: &F,
    cursor: &F::Cursor,
) -> std::io::Result<Vec<std::ffi::OsString>> {
    use std::os::unix::ffi::OsStrExt;
    let mut names = Vec::new();
    loop {
        fs.clear_errno();
        let Some(name) = fs.readdir(cursor) else {
            let errno = fs.errno();
            if errno != 0 {
                return Err(std::io::Error::from_raw_os_error(errno));
            }
            return Ok(names);
        };
        let bytes = name.as_os_str().as_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(name);
    }
}

/// Open a fresh listing of `dir` and collect its entry names (excluding
/// `.`/`..`). The stream is closed exactly once, on the success and error
/// paths alike; a failed `open` owns its own fd cleanup.
#[cfg(unix)]
pub(super) fn read_dir_names_with<F: DirReadFs>(
    fs: &F,
    dir: &std::os::fd::OwnedFd,
) -> std::io::Result<Vec<std::ffi::OsString>> {
    let cursor = fs.open(dir)?;
    let result = collect_dir_names(fs, &cursor);
    fs.close(cursor);
    result
}

/// Entry names of one directory fd (excluding `.`/`..`).
#[cfg(unix)]
pub(super) fn read_dir_names(
    dir: &std::os::fd::OwnedFd,
) -> std::io::Result<Vec<std::ffi::OsString>> {
    read_dir_names_with(&RealDirReadFs, dir)
}

/// `S_IFMT`/`S_IFLNK` are `u16` on macOS and `u32` on Linux; the casts are
/// necessary on one platform and redundant on the other.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn mode_is_symlink(mode: u32) -> bool {
    mode & (libc::S_IFMT as u32) == libc::S_IFLNK as u32
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn mode_is_dir(mode: u32) -> bool {
    mode & (libc::S_IFMT as u32) == libc::S_IFDIR as u32
}

/// `fstatat(AT_SYMLINK_NOFOLLOW)` mode of one entry.
#[cfg(unix)]
pub(super) fn fstatat_mode(
    dir: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name_c.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat.st_mode as u32)
}
