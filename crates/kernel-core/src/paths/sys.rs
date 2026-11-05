//! Small fd-relative filesystem primitives shared by the home gateway.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use super::guard::path_components;
use super::sandbox_home::SandboxHome;

/// Identity of a file or directory: `(st_dev, st_ino)`. Comparing identity
/// defeats every spelling of the same directory — case, NFD/NFC, symlinks,
/// firmlinks (`/System/Volumes/Data/…`), `/private/var` and hardlinked
/// spellings — because the kernel resolves them all to the same inode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct FileId {
    pub(super) dev: u64,
    pub(super) ino: u64,
}

/// `openat` with a mode argument, mapping `EEXIST` (exclusive) to `Ok(None)`.
#[cfg(unix)]
pub(super) fn openat_with_mode(
    dir: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<Option<std::os::fd::RawFd>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })?;
    // `openat` is variadic: the mode is promoted to `c_uint`.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            return Ok(None);
        }
        return Err(err);
    }
    Ok(Some(fd))
}

/// `unlinkat` on one verified parent directory.
#[cfg(unix)]
pub(super) fn unlinkat(dir: &std::os::fd::OwnedFd, name: &std::ffi::OsStr) -> std::io::Result<()> {
    unlinkat_flags(dir, name, 0)
}

/// `unlinkat` with explicit flags (`AT_REMOVEDIR` for a directory). Never
/// follows a link: a symlink entry is removed as a link.
#[cfg(unix)]
pub(super) fn unlinkat_flags(
    dir: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })?;
    // SAFETY: `name` is a NUL-terminated CString alive for the call and the
    // fd is borrowed from a live `OwnedFd`.
    let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Open the parent directory chain of `components` under the verified home,
/// creating missing directories. Strict `O_NOFOLLOW`: a symlink inside the
/// home is refused rather than followed.
#[cfg(unix)]
pub(super) fn open_rel_dir(
    home: &SandboxHome,
    components: &[OsString],
) -> std::io::Result<std::os::fd::OwnedFd> {
    open_rel_dir_inner(home, components, true)
}

/// Like [`open_rel_dir`] but never creates anything: a missing directory is
/// `NotFound`, and every component is still opened `O_NOFOLLOW`.
#[cfg(unix)]
pub(super) fn open_rel_dir_existing(
    home: &SandboxHome,
    components: &[OsString],
) -> std::io::Result<std::os::fd::OwnedFd> {
    open_rel_dir_inner(home, components, false)
}

#[cfg(unix)]
fn open_rel_dir_inner(
    home: &SandboxHome,
    components: &[OsString],
    create: bool,
) -> std::io::Result<std::os::fd::OwnedFd> {
    let mut dir = home.dir.try_clone()?;
    for name in components {
        dir = match openat_dir(&dir, name, true) {
            Ok(fd) => fd,
            Err(err) if create && err.raw_os_error() == Some(libc::ENOENT) => {
                // Tolerate a concurrent creator winning the mkdir race.
                match mkdirat(&dir, name, 0o700) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(err) => return Err(err),
                }
                openat_dir(&dir, name, true)?
            }
            Err(err) => return Err(err),
        };
    }
    Ok(dir)
}

/// Validate a sandbox-relative path: no absolute or parent components.
pub(super) fn relative_components(rel: &Path) -> std::io::Result<Vec<OsString>> {
    let mut out = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(name) => out.push(name.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_rel(rel));
            }
        }
    }
    if out.is_empty() {
        return Err(invalid_rel(rel));
    }
    Ok(out)
}

pub(super) fn invalid_rel(rel: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "sandbox-relative path must be a non-empty path inside the home: {}",
            rel.display()
        ),
    )
}

#[cfg(unix)]
pub(super) fn file_id(path: &Path) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|meta| FileId {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

#[cfg(not(unix))]
pub(super) fn file_id(_path: &Path) -> Option<FileId> {
    None
}

#[cfg(unix)]
pub(super) fn fd_file_id(dir: &std::os::fd::OwnedFd) -> Option<FileId> {
    use std::os::fd::AsRawFd;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(dir.as_raw_fd(), &mut stat) };
    if rc != 0 {
        return None;
    }
    Some(FileId {
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
    })
}

/// Open the home directory by path for re-verification: walk from `/`,
/// following ancestors (a legitimate symlink ancestor like `/var` is fine)
/// and refusing to follow a symlink at the leaf (`ELOOP`/`ENOTDIR` retry
/// resolves it, then the caller compares identity).
#[cfg(unix)]
pub(super) fn open_dir_by_path(home: &Path) -> std::io::Result<std::os::fd::OwnedFd> {
    let mut dir = open_base_dir(home)?;
    for name in path_components(home) {
        dir = match openat_dir(&dir, &name, true) {
            Ok(fd) => fd,
            Err(err) if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
                openat_dir(&dir, &name, false)?
            }
            Err(err) => return Err(err),
        };
    }
    Ok(dir)
}

#[cfg(unix)]
pub(super) fn open_base_dir(home: &Path) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let path = if home.is_absolute() { c"/" } else { c"." };
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(unix)]
pub(super) fn openat_dir(
    dir: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
    nofollow: bool,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })?;
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(unix)]
pub(super) fn mkdirat(
    dir: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
    mode: libc::mode_t,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })?;
    let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn fchmod_0700(dir: &std::os::fd::OwnedFd) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let rc = unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn fd_real_path(dir: &std::os::fd::OwnedFd) -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut buf: Vec<libc::c_char> = vec![0; libc::PATH_MAX as usize];
    let rc = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr()) };
    Some(PathBuf::from(OsStr::from_bytes(cstr.to_bytes())))
}

#[cfg(target_os = "linux")]
pub(super) fn fd_real_path(dir: &std::os::fd::OwnedFd) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd())).ok()
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
pub(super) fn fd_real_path(_dir: &std::os::fd::OwnedFd) -> Option<PathBuf> {
    None
}
