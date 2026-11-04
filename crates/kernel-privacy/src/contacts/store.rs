//! Where a contact index is kept between sessions: memory only, never plain files.

use std::fmt;

use super::ContactIndex;

/// Where a contact index is kept between sessions.
///
/// **The persistent store must be the encrypted local store (SQLCipher, slice
/// 4), never plain files.** A contact index holds real names, e-mail addresses
/// and phone numbers. It never leaves this machine: it is not written to a plain
/// file, a cache, a log, or a cloud payload, and no model is ever given it.
///
/// A seam for the caller's own store; the kernel ships [`MemoryContactStore`].
pub trait ContactStore {
    /// Load the saved index, or an empty one when nothing was saved.
    fn load(&self) -> Result<ContactIndex, ContactStoreError>;

    /// Replace the saved index with `index`.
    fn save(&mut self, index: &ContactIndex) -> Result<(), ContactStoreError>;
}

/// A store could not be read or written. Carries no contact data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContactStoreError {
    /// A fixed description of the failure.
    pub reason: &'static str,
}

impl fmt::Display for ContactStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}

impl std::error::Error for ContactStoreError {}

/// An in-memory store: it keeps a copy of the index for this session and writes
/// nothing to disk. It is the only implementation in this crate.
#[derive(Clone, Default)]
pub struct MemoryContactStore {
    saved: ContactIndex,
}

impl ContactStore for MemoryContactStore {
    fn load(&self) -> Result<ContactIndex, ContactStoreError> {
        Ok(self.saved.clone())
    }

    fn save(&mut self, index: &ContactIndex) -> Result<(), ContactStoreError> {
        self.saved = index.clone();
        Ok(())
    }
}
