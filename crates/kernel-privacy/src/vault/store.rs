//! Opening the vault, and the locking, sealing and generation-checked record
//! storage every public operation goes through.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use kernel_core::SandboxHome;

use crate::anonymize::TokenMap;

use super::codec::{decode, decode_manifest, encode, encode_manifest};
use super::key::{create_key, read_key};
use super::paths::{additional_data, lock_file, record_rel, record_slots, slot_for};
use super::{crash_point, next_generation, CrashPoint, Manifest, Record, Vault, VaultError};
use super::{KEY_FILE, MANIFEST_FILE, MANIFEST_LABEL, SESSIONS_DIR};

impl Vault {
    /// Opens the vault in `dir`, creating it on first use.
    ///
    /// `dir` is opened as a [`SandboxHome`], which creates it 0700 when missing.
    /// A missing key file gets a fresh 0600 key, but only when no record exists
    /// yet. A missing key beside records is an error, because a new key would
    /// orphan them silently.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, VaultError> {
        let home = SandboxHome::open(dir.as_ref())?;
        // Held across the key and manifest creation below, so two first opens
        // cannot both create state, and one cannot clobber the other's manifest.
        let _lock = lock_file(&home)?;
        let key = if home.exists_no_follow(Path::new(KEY_FILE))? {
            read_key(&home.path().join(KEY_FILE))?
        } else if !record_slots(home.path())?.is_empty() {
            return Err(VaultError::KeyUnavailable(
                "key file is missing but records exist",
            ));
        } else {
            create_key(&home)?
        };
        let vault = Self { home, key };
        // The manifest exists before the first record: a crash in the first write
        // must not leave a record with no manifest beside it, which reads refuse.
        if !vault.home.exists_no_follow(Path::new(MANIFEST_FILE))?
            && record_slots(vault.home.path())?.is_empty()
        {
            vault.store_manifest(&Manifest::default())?;
        }
        Ok(vault)
    }

    pub(super) fn record_path(&self, slot: &str) -> PathBuf {
        self.home.path().join(record_rel(slot))
    }

    /// The advisory lock every public operation holds across its reads and
    /// writes. It is released when the returned file is dropped, on the error
    /// paths too.
    pub(super) fn lock(&self) -> Result<fs::File, VaultError> {
        lock_file(&self.home)
    }

    /// The manifest, or an empty one while the vault has no records. A missing
    /// manifest beside records is an error: deleting it must not reset every
    /// generation to zero.
    pub(super) fn load_manifest(&self) -> Result<Manifest, VaultError> {
        let sealed = match fs::read(self.home.path().join(MANIFEST_FILE)) {
            Ok(sealed) => sealed,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if record_slots(self.home.path())?.is_empty() {
                    return Ok(Manifest::default());
                }
                return Err(VaultError::Corrupt("manifest is missing but records exist"));
            }
            Err(err) => return Err(err.into()),
        };
        let plaintext = self.unseal(&additional_data(MANIFEST_LABEL), &sealed)?;
        decode_manifest(&plaintext)
    }

    fn store_manifest(&self, manifest: &Manifest) -> Result<(), VaultError> {
        let plaintext = encode_manifest(manifest)?;
        let sealed = self.seal(&additional_data(MANIFEST_LABEL), &plaintext)?;
        self.home
            .write_atomic(Path::new(MANIFEST_FILE), &sealed, 0o600)?;
        Ok(())
    }

    /// Seals the manifest with `slot` at `generation`.
    pub(super) fn set_generation(
        &self,
        manifest: &mut Manifest,
        slot: &str,
        generation: u64,
    ) -> Result<(), VaultError> {
        manifest.generations.insert(slot.to_owned(), generation);
        self.store_manifest(manifest)
    }

    /// The session's map, or `None` when it has no record.
    ///
    /// A record at the manifest's generation is current. One ahead of it is the
    /// newer half of a write that crashed before its manifest step: it is
    /// committed here, under the lock, and returned. A record below the
    /// generation is refused with [`VaultError::Rollback`]. Anything further
    /// ahead is an error.
    pub(super) fn checked_session(
        &self,
        manifest: &mut Manifest,
        session_id: &str,
    ) -> Result<Option<TokenMap>, VaultError> {
        let slot = slot_for(session_id);
        let Some(record) = self.open_record(&slot)? else {
            return Ok(None);
        };
        if record.session_id != session_id {
            return Err(VaultError::Corrupt("session id does not match its record"));
        }
        let current = manifest.generation(&slot);
        // Checked before any comparison: at `u64::MAX` there is no next generation
        // for the commit below, so the session is refused whatever its record holds.
        let ahead = next_generation(current)?;
        if record.generation == current {
            return Ok(Some(record.map));
        }
        if record.generation == ahead {
            self.set_generation(manifest, &slot, record.generation)?;
            return Ok(Some(record.map));
        }
        if record.generation < current {
            return Err(VaultError::Rollback);
        }
        Err(VaultError::Corrupt("record is ahead of the manifest"))
    }

    /// Reads and authenticates one record without checking its generation.
    /// `None` when the file does not exist.
    pub(super) fn open_record(&self, slot: &str) -> Result<Option<Record>, VaultError> {
        let sealed = match fs::read(self.record_path(slot)) {
            Ok(sealed) => sealed,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let plaintext = self.unseal(&additional_data(slot), &sealed)?;
        let record = decode(&plaintext)?;
        if slot_for(&record.session_id) != slot {
            return Err(VaultError::Corrupt("session id does not match its record"));
        }
        Ok(Some(record))
    }

    /// Replaces the session's record with `map`, under a generation past both the
    /// manifest and `replaces`, the generation of the record being replaced (0
    /// when there is none). The record goes first: a crash before the manifest
    /// step leaves it one generation ahead, and [`Vault::checked_session`] commits
    /// it on the next read. Nothing is lost, and the write is never half-visible.
    /// Fails with [`VaultError::GenerationExhausted`] before writing anything when
    /// that generation would pass `u64::MAX`.
    pub(super) fn write_session(
        &self,
        manifest: &mut Manifest,
        session_id: &str,
        map: &TokenMap,
        replaces: u64,
    ) -> Result<(), VaultError> {
        let slot = slot_for(session_id);
        let generation = next_generation(manifest.generation(&slot).max(replaces))?;
        let plaintext = encode(session_id, generation, map)?;
        let sealed = self.seal(&additional_data(&slot), &plaintext)?;
        self.home.create_dir_all(Path::new(SESSIONS_DIR))?;
        self.home.write_atomic(&record_rel(&slot), &sealed, 0o600)?;
        crash_point(CrashPoint::AfterRecordWrite)?;
        self.set_generation(manifest, &slot, generation)
    }

    /// Removes the session's record and returns whether one existed. The manifest
    /// goes first, past any record on disk, so a crash before the unlink leaves a
    /// record that is refused and never one that reads again. A retry removes it.
    /// Fails with [`VaultError::GenerationExhausted`] before anything is removed
    /// when that generation would pass `u64::MAX`.
    pub(super) fn remove_session(
        &self,
        manifest: &mut Manifest,
        session_id: &str,
    ) -> Result<bool, VaultError> {
        let slot = slot_for(session_id);
        let generation = next_generation(
            manifest
                .generation(&slot)
                .max(self.on_disk_generation(&slot)?),
        )?;
        self.set_generation(manifest, &slot, generation)?;
        crash_point(CrashPoint::AfterGenerationBump)?;
        Ok(self.home.remove_file(&record_rel(&slot))?)
    }

    /// The generation of the record on disk, or 0 when there is none. A record
    /// that cannot be authenticated is never served, so its generation is moot.
    fn on_disk_generation(&self, slot: &str) -> Result<u64, VaultError> {
        match self.open_record(slot) {
            Ok(record) => Ok(record.map_or(0, |record| record.generation)),
            Err(VaultError::Corrupt(_)) => Ok(0),
            Err(err) => Err(err),
        }
    }

    /// Removes the temp files that an interrupted write left in the vault and in
    /// `sessions/`. [`write_atomic`](kernel_core::SandboxHome::write_atomic) names
    /// its temp file `.<name>.tmp.<pid>.<stamp>`. Such a file was never renamed
    /// into place, so no record names it, but it holds ciphertext of the values
    /// that write carried. Erasure must reach it too. Called under the lock, so
    /// no write is in flight.
    pub(super) fn sweep_temp_files(&self) -> Result<(), VaultError> {
        for dir in [PathBuf::new(), PathBuf::from(SESSIONS_DIR)] {
            let entries = match fs::read_dir(self.home.path().join(&dir)) {
                Ok(entries) => entries,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err.into()),
            };
            for entry in entries {
                let name = entry?.file_name();
                let is_temp = name
                    .to_str()
                    .is_some_and(|name| name.starts_with('.') && name.contains(".tmp."));
                if is_temp {
                    self.home.remove_file(&dir.join(&name))?;
                }
            }
        }
        Ok(())
    }
}
