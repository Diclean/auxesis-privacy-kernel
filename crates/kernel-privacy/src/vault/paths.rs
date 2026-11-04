//! Vault file names, session slots and the vault-wide advisory lock.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use kernel_core::SandboxHome;
use sha2::{Digest, Sha256};

use super::{VaultError, LOCK_FILE, MAGIC, RECORD_EXT, SESSIONS_DIR, SLOT_DOMAIN};

/// Opens `vault.lock` and takes the vault-wide `flock` on it.
pub(super) fn lock_file(home: &SandboxHome) -> Result<fs::File, VaultError> {
    let file = home.open_append(Path::new(LOCK_FILE), 0o600)?;
    file.lock()?;
    Ok(file)
}

/// The slots of every record file under `dir/sessions`, by file stem.
pub(super) fn record_slots(dir: &Path) -> Result<Vec<String>, VaultError> {
    let entries = match fs::read_dir(dir.join(SESSIONS_DIR)) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut slots = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension() == Some(OsStr::new(RECORD_EXT)) {
            if let Some(slot) = path.file_stem().and_then(OsStr::to_str) {
                slots.push(slot.to_owned());
            }
        }
    }
    Ok(slots)
}

/// A record's path relative to the vault root.
pub(super) fn record_rel(slot: &str) -> PathBuf {
    Path::new(SESSIONS_DIR).join(format!("{slot}.{RECORD_EXT}"))
}

/// The record file name for a session: hex SHA-256 over a domain tag and the id.
pub(super) fn slot_for(session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(session_id.as_bytes());
    hex(&hasher.finalize())
}

pub(super) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The AEAD additional data for one file: the magic, then the file's label (a
/// session slot, or `manifest`).
pub(super) fn additional_data(label: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + label.len());
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(label.as_bytes());
    aad
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    #[test]
    fn old_version_vector_slot() {
        assert_eq!(
            slot_for("fixture-session"),
            "ca25378cd0a6b01071441fd3171e8f7afc4c4c3f5aa813580196698295de3e9a"
        );
    }
}
