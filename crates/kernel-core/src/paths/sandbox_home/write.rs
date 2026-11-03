//! Write and create operations below the verified home.

use std::ffi::OsString;
use std::path::Path;

use super::SandboxHome;
use crate::paths::sys::{
    invalid_rel, mkdirat, open_rel_dir, openat_with_mode, relative_components, unlinkat,
};

impl SandboxHome {
    /// Create the file `rel` (relative to the home) with `data` and `mode`,
    /// truncating an existing file. Never follows a symlink.
    pub fn write(&self, rel: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
        self.reverify()?;

        self.write_inner(rel, data, mode, false).map(|_| ())
    }

    /// Like [`SandboxHome::write`] but fails with `AlreadyExists` instead of
    /// truncating; returns `false` when the file already exists.
    pub fn write_new(&self, rel: &Path, data: &[u8], mode: u32) -> std::io::Result<bool> {
        self.reverify()?;

        self.write_inner(rel, data, mode, true)
    }

    /// Create the directory `rel` (parents must exist); `false` when it
    /// already exists.
    pub fn create_dir(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;

        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            let dir = open_rel_dir(self, dirs)?;
            match mkdirat(&dir, name, 0o700) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(err) => Err(err),
            }
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            match std::fs::create_dir(path) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(err) => Err(err),
            }
        }
    }

    /// Atomically and durably replace `rel` with `data`: temp file, fsync,
    /// `renameat` in the verified parent, then fsync of that parent. Mode `mode`.
    pub fn write_atomic(&self, rel: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
        self.write_atomic_with_pre_rename_check(rel, data, mode, || Ok(()))
    }

    /// Atomically replace `rel` after syncing a temporary file, running
    /// `before_rename_check` immediately before the final rename. If the check
    /// fails, the temporary file is removed and the existing destination stays
    /// in place.
    pub fn write_atomic_with_pre_rename_check(
        &self,
        rel: &Path,
        data: &[u8],
        mode: u32,
        before_rename_check: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        self.reverify()?;

        use std::io::Write as _;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            use std::os::unix::ffi::OsStrExt;
            let dir = open_rel_dir(self, dirs)?;
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let temp = OsString::from(format!(
                ".{}.tmp.{}.{stamp}",
                name.to_string_lossy(),
                std::process::id()
            ));
            let flags =
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
            let Some(fd) = openat_with_mode(&dir, &temp, flags, mode as libc::mode_t)? else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "atomic temp file already exists",
                ));
            };
            let write_result = (|| -> std::io::Result<()> {
                let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
                let metadata = file.metadata()?;
                if !metadata.is_file() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "atomic target is not a regular file",
                    ));
                }
                let chmod = unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) };
                if chmod != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                file.write_all(data)?;
                file.sync_all()
            })();
            if let Err(err) = write_result {
                let _ = unlinkat(&dir, &temp);
                return Err(err);
            }
            let from = std::ffi::CString::new(temp.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let to = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            if let Err(err) = before_rename_check() {
                let _ = unlinkat(&dir, &temp);
                return Err(err);
            }
            let rc = unsafe {
                libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr())
            };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                let _ = unlinkat(&dir, &temp);
                return Err(err);
            }
            // The rename is a directory entry change: it survives a crash only
            // once the directory itself is synced.
            if unsafe { libc::fsync(dir.as_raw_fd()) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let parent = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name));
            let temp = parent.join(format!(
                ".{}.tmp.{}",
                name.to_string_lossy(),
                std::process::id()
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = options.open(&temp)?;
            file.write_all(data)?;
            file.sync_all()?;
            drop(file);
            if let Err(err) = before_rename_check() {
                let _ = std::fs::remove_file(&temp);
                return Err(err);
            }
            std::fs::rename(&temp, parent.join(name))
        }
    }

    /// Create `rel` and every missing parent under the home (`0700`).
    pub fn create_dir_all(&self, rel: &Path) -> std::io::Result<()> {
        self.reverify()?;

        let components = relative_components(rel)?;
        #[cfg(unix)]
        {
            let _ = open_rel_dir(self, &components)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let path = components
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name));
            std::fs::create_dir_all(path)
        }
    }

    fn write_inner(
        &self,
        rel: &Path,
        data: &[u8],
        mode: u32,
        exclusive: bool,
    ) -> std::io::Result<bool> {
        use std::io::Write as _;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            let dir = open_rel_dir(self, dirs)?;
            let flags = libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | if exclusive {
                    libc::O_EXCL
                } else {
                    libc::O_TRUNC
                };
            // `openat_with_mode` maps EEXIST (exclusive) to `None`: callers
            // using `write_new` want `false`, not an error.
            let Some(fd) = openat_with_mode(&dir, name, flags, mode as libc::mode_t)? else {
                return Ok(false);
            };
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            file.write_all(data)?;
            file.sync_all()?;
            Ok(true)
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(mode);
            }
            if exclusive {
                options.create_new(true);
            } else {
                options.truncate(true);
            }
            match options.open(path) {
                Ok(mut file) => {
                    file.write_all(data)?;
                    Ok(true)
                }
                Err(err) if exclusive && err.kind() == std::io::ErrorKind::AlreadyExists => {
                    Ok(false)
                }
                Err(err) => Err(err),
            }
        }
    }
}
