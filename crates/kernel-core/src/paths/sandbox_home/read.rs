//! Read-only access to files and directories below the verified home.

use std::path::Path;

use super::SandboxHome;
use crate::paths::sys::{
    invalid_rel, open_rel_dir, open_rel_dir_existing, openat_with_mode, relative_components,
};

impl SandboxHome {
    /// Open `rel` for append (creating with `mode`), fd-relative and
    /// `O_NOFOLLOW`.
    pub fn open_append(&self, rel: &Path, mode: u32) -> std::io::Result<std::fs::File> {
        self.reverify()?;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            let dir = open_rel_dir(self, dirs)?;
            let flags = libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_APPEND
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW;
            let Some(fd) = openat_with_mode(&dir, name, flags, mode as libc::mode_t)? else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "append target exists",
                ));
            };
            Ok(unsafe { std::fs::File::from_raw_fd(fd) })
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            let mut options = std::fs::OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(mode);
            }
            options.open(path)
        }
    }

    /// Open `rel` for reading relative to the verified home descriptor.
    ///
    /// On Unix the leaf is opened with `O_NOFOLLOW | O_NONBLOCK`, then the
    /// returned descriptor is `fstat`ed before it is returned. This refuses
    /// symlinks, FIFOs, devices, directories and oversized files without a
    /// path-based check/read race. Missing parent directories are created
    /// (`0700`); use [`SandboxHome::open_read_existing`] when a read must not
    /// create anything.
    pub fn open_read(&self, rel: &Path, max_bytes: u64) -> std::io::Result<std::fs::File> {
        self.open_read_inner(rel, max_bytes, true)
    }

    /// Like [`SandboxHome::open_read`] but never creates a missing directory:
    /// a path whose parent chain does not exist is `NotFound`.
    pub fn open_read_existing(&self, rel: &Path, max_bytes: u64) -> std::io::Result<std::fs::File> {
        self.open_read_inner(rel, max_bytes, false)
    }

    fn open_read_inner(
        &self,
        rel: &Path,
        max_bytes: u64,
        create_dirs: bool,
    ) -> std::io::Result<std::fs::File> {
        self.reverify()?;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            let dir = if create_dirs {
                open_rel_dir(self, dirs)?
            } else {
                open_rel_dir_existing(self, dirs)?
            };
            let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
            let Some(fd) = openat_with_mode(&dir, name, flags, 0)? else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "read target unexpectedly exists",
                ));
            };
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "read target is not a regular file",
                ));
            }
            if metadata.len() > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "read target is too large",
                ));
            }
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            let _ = create_dirs;
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "read target is a symlink",
                ));
            }
            let file = std::fs::OpenOptions::new().read(true).open(path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "read target is not a bounded regular file",
                ));
            }
            Ok(file)
        }
    }

    /// Open the existing directory `rel` with `O_NOFOLLOW | O_DIRECTORY` on
    /// every component from the home fd: a link or file on the way is
    /// `PermissionDenied` (as in `remove_dir_all`), a missing one `NotFound`.
    #[cfg(unix)]
    pub fn open_dir(&self, rel: &Path) -> std::io::Result<std::fs::File> {
        self.reverify()?;
        let components = relative_components(rel)?;
        open_rel_dir_existing(self, &components)
            .map(std::fs::File::from)
            .map_err(|err| super::remove::link_refusal(rel, err))
    }

    /// Whether `rel` exists in the verified home, without following a leaf
    /// symlink (a dangling symlink counts as present — the kill switch is
    /// fail-safe).
    pub fn exists_no_follow(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let dir = open_rel_dir(self, dirs)?;
            let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    name_c.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc == 0 {
                return Ok(true);
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(false);
            }
            Err(err)
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            Ok(std::fs::symlink_metadata(path).is_ok())
        }
    }
}
