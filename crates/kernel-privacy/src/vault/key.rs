//! The vault key file: reading it back, creating it once, and randomness.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use kernel_core::SandboxHome;
use zeroize::Zeroizing;

use super::{VaultError, KEY_FILE, KEY_LEN};

pub(super) fn read_key(path: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|_| VaultError::KeyUnavailable("key file is unreadable"))?;
    if !meta.is_file() {
        return Err(VaultError::KeyUnavailable("key path is not a regular file"));
    }
    if (meta.permissions().mode() & 0o077) != 0 {
        return Err(VaultError::KeyUnavailable(
            "key file is readable by group or others",
        ));
    }
    let bytes = Zeroizing::new(
        fs::read(path).map_err(|_| VaultError::KeyUnavailable("key file is unreadable"))?,
    );
    if bytes.len() != KEY_LEN {
        return Err(VaultError::KeyUnavailable("key file has the wrong length"));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub(super) fn create_key(home: &SandboxHome) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    random(&mut key[..])?;
    if !home.write_new(Path::new(KEY_FILE), &key[..], 0o600)? {
        return Err(VaultError::KeyUnavailable(
            "key file appeared during creation",
        ));
    }
    Ok(key)
}

pub(super) fn random(buf: &mut [u8]) -> io::Result<()> {
    getrandom::getrandom(buf).map_err(|_| io::Error::other("no operating-system randomness"))
}
