//! The vault error type: what can fail, and why no message carries a value.

use std::fmt;
use std::io;

/// Why a vault operation failed. No message carries a value or the key.
#[derive(Debug)]
pub enum VaultError {
    /// The key file is missing, unreadable, the wrong size or readable by
    /// someone other than its owner, or it is gone while records exist. Private
    /// stores stay locked.
    KeyUnavailable(&'static str),
    /// A record or the manifest is truncated, not a vault file, fails
    /// authentication (wrong key, tampered, or moved to another place) or does
    /// not parse. It is never read as an empty map.
    Corrupt(&'static str),
    /// A record is older than its session's generation: a copy from before a
    /// write or an erasure. It is refused, never restored.
    Rollback,
    /// The session's generation is at `u64::MAX`, so the next write or erasure
    /// has no larger generation to name. Nothing is written: a generation never
    /// wraps to zero, which would let an older copy pass the rollback check.
    GenerationExhausted,
    /// A token is already mapped to a different value in this session. Nothing
    /// was written. The caller must re-tokenise the message.
    TokenConflict,
    /// A file-system operation failed.
    Io(io::Error),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyUnavailable(why) => write!(f, "vault key unavailable: {why}"),
            Self::Corrupt(why) => write!(f, "vault record rejected: {why}"),
            Self::Rollback => write!(
                f,
                "vault record rejected: older than the session's last write or erasure"
            ),
            Self::GenerationExhausted => write!(f, "vault session generation is exhausted"),
            Self::TokenConflict => write!(
                f,
                "vault token conflict: a token already maps to another value"
            ),
            Self::Io(err) => write!(f, "vault I/O failed: {err}"),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for VaultError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
