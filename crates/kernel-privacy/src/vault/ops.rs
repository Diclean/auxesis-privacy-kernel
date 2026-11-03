//! The public session operations: record a map, look it up, forget a session,
//! and erase one value from every session.

use std::collections::HashSet;

use crate::anonymize::TokenMap;

use super::merge::{erases, merge};
use super::paths::record_slots;
use super::{Vault, VaultError};

impl Vault {
    /// Adds `map` to the session's record. Tokens already recorded keep their
    /// first surface form, and every occurrence is appended, so a replayed
    /// message does not change the entries.
    ///
    /// Fails with [`VaultError::TokenConflict`] and writes nothing when a token
    /// of `map` is already mapped to a different value in this session. The
    /// caller must re-tokenise the message in that case. Fails with
    /// [`VaultError::Rollback`] when the session's record is stale.
    pub fn record(&self, session_id: &str, map: &TokenMap) -> Result<(), VaultError> {
        let _lock = self.lock()?;
        let mut manifest = self.load_manifest()?;
        let mut merged = self
            .checked_session(&mut manifest, session_id)?
            .unwrap_or_default();
        merge(&mut merged, map)?;
        if merged.is_empty() {
            return Ok(());
        }
        self.write_session(&mut manifest, session_id, &merged, 0)
    }

    /// The session's token map. A session with no record yields an empty map;
    /// a record that fails to open, or is stale, is an error.
    pub fn lookup(&self, session_id: &str) -> Result<TokenMap, VaultError> {
        let _lock = self.lock()?;
        let mut manifest = self.load_manifest()?;
        Ok(self
            .checked_session(&mut manifest, session_id)?
            .unwrap_or_default())
    }

    /// Deletes one session's record and raises its generation, so an older copy
    /// of the record is refused from now on. Returns `false` if the record did
    /// not exist.
    pub fn forget_session(&self, session_id: &str) -> Result<bool, VaultError> {
        let _lock = self.lock()?;
        let mut manifest = self.load_manifest()?;
        self.sweep_temp_files()?;
        self.remove_session(&mut manifest, session_id)
    }

    /// Erases one person from every session. A token is removed when any value
    /// kept under it equals `value` once both are folded under the token's own
    /// kind and casefolded. Every surface kept under a removed token goes too,
    /// so `0612345678` also removes `06 12 34 56 78` when they share a token.
    /// Returns the number of token mappings removed across all sessions.
    ///
    /// Any record that cannot be opened is an error. The erasure never skips a
    /// record silently. Stale records and records ahead of the manifest are
    /// erased too, because their values are still on disk: the erased copy is
    /// written past the record's generation, so the original never reads again.
    /// Leftover temp files from interrupted writes are removed as well, since
    /// they hold ciphertext of values that may be erased here.
    ///
    /// A record whose session is at `u64::MAX` cannot be rewritten, so the call
    /// fails with [`VaultError::GenerationExhausted`]. Records the walk erased
    /// before that stay erased, and the caller must treat the erasure as incomplete.
    pub fn forget_value(&self, value: &str) -> Result<usize, VaultError> {
        let _lock = self.lock()?;
        let mut manifest = self.load_manifest()?;
        self.sweep_temp_files()?;
        let mut removed = 0;
        for slot in record_slots(self.home.path())? {
            let Some(record) = self.open_record(&slot)? else {
                continue;
            };
            let doomed: HashSet<&str> = record
                .map
                .iter()
                .chain(record.map.occurrences())
                .filter(|(token, original)| erases(token, original, value))
                .map(|(token, _)| token.as_str())
                .collect();
            if doomed.is_empty() {
                continue;
            }
            removed += record
                .map
                .iter()
                .filter(|(token, _)| doomed.contains(token.as_str()))
                .count();
            let mut kept = TokenMap::default();
            for (token, original) in record.map.iter() {
                if !doomed.contains(token.as_str()) {
                    kept.push_entry(token.clone(), original.clone());
                }
            }
            for (token, original) in record.map.occurrences() {
                if !doomed.contains(token.as_str()) {
                    kept.push_occurrence(token.clone(), original.clone());
                }
            }
            if kept.is_empty() {
                self.remove_session(&mut manifest, &record.session_id)?;
            } else {
                self.write_session(&mut manifest, &record.session_id, &kept, record.generation)?;
            }
        }
        Ok(removed)
    }
}
