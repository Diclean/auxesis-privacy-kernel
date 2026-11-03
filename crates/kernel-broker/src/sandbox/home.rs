//! The real home of the daemon user, and the passwd fallback that keeps the
//! sensitive-path denies from being dropped.

use std::path::{Path, PathBuf};

/// The real (canonical) home of the daemon user.
///
/// `HOME` is used when it names a real directory that is not `/`; otherwise
/// the passwd entry for the effective user is the fallback, so an unset or
/// mangled `HOME` cannot silently drop the whole sensitive-path deny list.
/// If even that fails, the drop is logged loudly (the caller sees `None` and
/// the profile simply has no home denies).
pub(super) fn real_home() -> Option<PathBuf> {
    real_home_from(std::env::var_os("HOME").as_deref())
}

/// Testable core of [`real_home`]: the `HOME` value is passed in.
pub(super) fn real_home_from(env_home: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    if let Some(home) = env_home {
        if let Ok(home) = PathBuf::from(home).canonicalize() {
            if home.is_dir() && home != Path::new("/") {
                return Some(home);
            }
        }
    }
    match passwd_home() {
        Some(home) => {
            tracing::warn!(
                "shell: HOME is unset or unusable; using the passwd home {} for the \
                 sensitive-path deny list",
                home.display()
            );
            Some(home)
        }
        None => {
            tracing::warn!(
                "shell: HOME is unset or unusable and the passwd home could not be \
                 resolved; sensitive-path denies are NOT applied to this command"
            );
            None
        }
    }
}

/// The home directory from the passwd entry of the effective user, canonical.
#[cfg(unix)]
pub(super) fn passwd_home() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let uid = unsafe { libc::geteuid() };
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    let home = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
    let home = home.canonicalize().ok()?;
    (home.is_dir() && home != Path::new("/")).then_some(home)
}

#[cfg(not(unix))]
pub(super) fn passwd_home() -> Option<PathBuf> {
    None
}
