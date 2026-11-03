//! Removal operations below the verified home.

use std::path::Path;

use super::SandboxHome;
use crate::paths::sys::{invalid_rel, open_rel_dir, openat_dir, relative_components};

impl SandboxHome {
    /// Remove the directory `rel` (must be empty); `false` when it did not
    /// exist.
    pub fn remove_dir(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let dir = open_rel_dir(self, dirs)?;
            let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let rc =
                unsafe { libc::unlinkat(dir.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::NotFound {
                    return Ok(false);
                }
                return Err(err);
            }
            Ok(true)
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            match std::fs::remove_dir(path) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(err) => Err(err),
            }
        }
    }

    /// Recursively remove the directory `rel`, fd-checked: a symlinked child
    /// is refused, and the tree is removed through the verified fd's real
    /// path (`F_GETPATH`), never the configured path string.
    pub fn remove_dir_all(&self, rel: &Path) -> std::io::Result<()> {
        self.reverify()?;
        let components = relative_components(rel)?;
        #[cfg(unix)]
        {
            let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
            let parent = open_rel_dir(self, dirs)?;
            match openat_dir(&parent, name, true) {
                Ok(fd) => drop(fd),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err)
                    if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) =>
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "refus de sandbox : {} est un lien symbolique. \
                             / sandbox refused: {} is a symlink.",
                            rel.display(),
                            rel.display()
                        ),
                    ));
                }
                Err(err) => return Err(err),
            }
            let real = self.real_path()?;
            let target = components.iter().fold(real, |acc, part| acc.join(part));
            std::fs::remove_dir_all(target)
        }
        #[cfg(not(unix))]
        {
            let target = components
                .iter()
                .fold(self.home.clone(), |acc, part| acc.join(part));
            std::fs::remove_dir_all(target)
        }
    }

    /// Remove the file `rel`; `false` when it did not exist.
    pub fn remove_file(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;

        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let dir = open_rel_dir(self, dirs)?;
            let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::NotFound {
                    return Ok(false);
                }
                return Err(err);
            }
            Ok(true)
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            match std::fs::remove_file(path) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(err) => Err(err),
            }
        }
    }
}
