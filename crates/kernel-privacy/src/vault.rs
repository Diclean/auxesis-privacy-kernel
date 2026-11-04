//! Encrypted per-session vault for token ↔ value mappings.
//!
//! The vault keeps one sealed record per session: the [`TokenMap`] that
//! [`Anonymizer::anonymize`](crate::Anonymizer::anonymize) produced for that
//! session. Records are sealed with AES-256-GCM under a random 256-bit key in
//! `vault.key` (mode 0600). The caller picks the directory, usually one derived
//! from `AUXESIS_HOME`; nothing here reads the Keychain. A missing, unreadable
//! or corrupt key, and a record that fails authentication, are errors. They are
//! never read as an empty map.
//!
//! Layout under the vault directory (mode 0700):
//!
//! * `vault.key`: 32 random bytes, mode 0600;
//! * `vault.lock`: the advisory lock file, mode 0600 (see *Concurrency*);
//! * `manifest.bin`: the sealed manifest, mode 0600, mapping each session slot
//!   to its current generation;
//! * `sessions/<slot>.bin`: `MAGIC ‖ nonce ‖ ciphertext ‖ tag`, one file per
//!   session. `slot` is the hex SHA-256 of a domain tag and the session id, so
//!   file names reveal neither the id nor any value.
//!
//! The AEAD additional data is `MAGIC ‖ slot` for a record and `MAGIC ‖
//! "manifest"` for the manifest, so a file copied or renamed into another place
//! fails authentication. The sealed record also carries its session id and its
//! generation, and every read checks both.
//!
//! **Rollback and crashes.** A record carries the generation it was written
//! under; the manifest carries each slot's current generation. A record older
//! than its slot's generation is a copy from before a write or an erasure, and it
//! is refused with [`VaultError::Rollback`].
//!
//! * **A write replaces the record first, then raises the manifest** to the new
//!   generation. A crash in between leaves the record one generation ahead of the
//!   manifest. The record is then the newer write, so the next read commits it by
//!   raising the manifest, under the lock. Until that read, a pre-write copy of
//!   the record restored by someone with write access to the vault directory
//!   would pass. That is the whole-directory case excluded below, limited to the
//!   crash window.
//! * **A removal raises the manifest first, then unlinks the record.** A crash
//!   after the raise leaves the record on disk but refused, so an erased record
//!   can never read again. The session answers [`VaultError::Rollback`] until a
//!   retry of [`Vault::forget_session`] or [`Vault::forget_value`] unlinks the
//!   leftover file. The session is refused, not empty, in that window.
//! * **A rewrite that keeps some entries is a write**, so it takes the write
//!   order above. A crash there commits the erasure.
//! * **A crash before a rename leaves a temp file** holding the ciphertext of
//!   that write. No record names it, and every erasure removes such files.
//!
//! **Exhaustion.** Generations are `u64` and never wrap. A write or an erasure
//! that would pass `u64::MAX` fails with [`VaultError::GenerationExhausted`]
//! before it writes anything. At `u64::MAX` every operation on the session is
//! refused, reads included, so a wrapped generation can never let an older copy
//! pass as current.
//!
//! The raise past any record on disk is also what keeps a copy of a deleted
//! record refused. Rolling back the whole vault directory, manifest included, is
//! out of scope: the FileVault and backup policy covers it.
//!
//! **Concurrency.** Every public operation holds one vault-wide `flock` on
//! `vault.lock` from its first read to its last write. It is vault-wide rather
//! than per session because the manifest is shared by every session.
//!
//! Every write goes through [`kernel_core::SandboxHome`], the verified home handle
//! that anchors writes to a directory descriptor, so a symlink swapped into the
//! tree cannot redirect them (the write-gateway rule). Records and the manifest
//! are replaced by write-then-rename, fsynced before and after the rename, so a
//! torn write never leaves a partial file and a finished write survives a crash.
//!
//! Unix only (macOS is the target): the modes above use `std::os::unix` APIs.

#[cfg(test)]
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
#[cfg(test)]
use std::io;

use kernel_core::SandboxHome;
use zeroize::Zeroizing;

use crate::anonymize::TokenMap;

mod codec;
mod crypto;
mod error;
mod key;
mod merge;
mod ops;
mod paths;
mod store;

#[cfg(test)]
mod tests;

pub use error::VaultError;

const KEY_FILE: &str = "vault.key";
const LOCK_FILE: &str = "vault.lock";
const MANIFEST_FILE: &str = "manifest.bin";
const MANIFEST_LABEL: &str = "manifest";
const SESSIONS_DIR: &str = "sessions";
const RECORD_EXT: &str = "bin";
const MAGIC: &[u8; 8] = b"AXVAULT1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SLOT_DOMAIN: &[u8] = b"auxesis.vault.session.v1\0";
const RECORD_VERSION: u8 = 2;
const MANIFEST_VERSION: u8 = 1;

/// The encrypted session vault rooted at one directory.
pub struct Vault {
    home: SandboxHome,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("dir", &self.home.path())
            .field("key", &"<redacted>")
            .finish()
    }
}

/// The generation each session slot is at. A record below its slot's
/// generation is stale.
#[derive(Default)]
struct Manifest {
    generations: BTreeMap<String, u64>,
}

impl Manifest {
    fn generation(&self, slot: &str) -> u64 {
        self.generations.get(slot).copied().unwrap_or(0)
    }
}

/// The generation after `current`. Fails at `u64::MAX` rather than panicking or
/// wrapping to zero, since a wrapped generation would pass the rollback check.
fn next_generation(current: u64) -> Result<u64, VaultError> {
    current
        .checked_add(1)
        .ok_or(VaultError::GenerationExhausted)
}

/// A decrypted record: its session, its generation and its map.
struct Record {
    session_id: String,
    generation: u64,
    map: TokenMap,
}

/// The points a test can make an operation fail at, as if the process had died
/// there. Each sits between two durable steps of a write or an erasure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrashPoint {
    /// After a record is replaced, before the manifest names its generation.
    AfterRecordWrite,
    /// After an erasure raised the manifest, before the record is unlinked.
    AfterGenerationBump,
}

#[cfg(test)]
thread_local! {
    /// The crash point this thread will hit next, if a test armed one.
    static CRASH_AT: Cell<Option<CrashPoint>> = const { Cell::new(None) };
}

/// Fails with an injected error when a test armed `point` on this thread, and
/// disarms it. Otherwise does nothing.
#[cfg(test)]
fn crash_point(point: CrashPoint) -> Result<(), VaultError> {
    if CRASH_AT.with(|armed| armed.get() == Some(point)) {
        CRASH_AT.with(|armed| armed.set(None));
        return Err(VaultError::Io(io::Error::other("injected crash")));
    }
    Ok(())
}

#[cfg(not(test))]
fn crash_point(_point: CrashPoint) -> Result<(), VaultError> {
    Ok(())
}
