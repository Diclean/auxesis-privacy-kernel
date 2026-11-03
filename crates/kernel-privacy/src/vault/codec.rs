//! The plaintext format inside a sealed record and manifest: encode and decode.

use std::collections::BTreeMap;
use std::io;

use zeroize::Zeroizing;

use crate::anonymize::TokenMap;

use super::{Manifest, Record, VaultError, MANIFEST_VERSION, RECORD_VERSION};

/// Record plaintext layout: version byte, session id, generation, entries,
/// occurrences. Every string is a big-endian `u32` length then UTF-8 bytes; a
/// pair list is a `u32` count then pairs; the generation is a big-endian `u64`.
pub(super) fn encode(
    session_id: &str,
    generation: u64,
    map: &TokenMap,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut out = Zeroizing::new(vec![RECORD_VERSION]);
    put_bytes(&mut out, session_id.as_bytes())?;
    out.extend_from_slice(&generation.to_be_bytes());
    put_pairs(&mut out, map)?;
    put_pairs(&mut out, map.occurrences())?;
    Ok(out)
}

/// Manifest plaintext layout: version byte, a `u32` count, then one
/// `(slot, generation)` pair per session.
pub(super) fn encode_manifest(manifest: &Manifest) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut out = Zeroizing::new(vec![MANIFEST_VERSION]);
    let count = u32::try_from(manifest.generations.len())
        .map_err(|_| VaultError::Io(io::Error::other("too many sessions")))?;
    out.extend_from_slice(&count.to_be_bytes());
    for (slot, generation) in &manifest.generations {
        put_bytes(&mut out, slot.as_bytes())?;
        out.extend_from_slice(&generation.to_be_bytes());
    }
    Ok(out)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), VaultError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| VaultError::Io(io::Error::other("record field too long")))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_pairs(out: &mut Vec<u8>, pairs: &[(String, String)]) -> Result<(), VaultError> {
    let count = u32::try_from(pairs.len())
        .map_err(|_| VaultError::Io(io::Error::other("too many record entries")))?;
    out.extend_from_slice(&count.to_be_bytes());
    for (token, original) in pairs {
        put_bytes(out, token.as_bytes())?;
        put_bytes(out, original.as_bytes())?;
    }
    Ok(())
}

/// Parses a plaintext record. A decode error drops the partly built map, which
/// zeroes what it had read.
pub(super) fn decode(plaintext: &[u8]) -> Result<Record, VaultError> {
    let mut reader = Reader(plaintext);
    if reader.take(1)?[0] != RECORD_VERSION {
        return Err(VaultError::Corrupt("unknown record version"));
    }
    let session_id = reader.string()?;
    let generation = reader.u64()?;
    let mut map = TokenMap::default();
    reader.pairs(|token, original| map.push_entry(token, original))?;
    reader.pairs(|token, original| map.push_occurrence(token, original))?;
    if !reader.0.is_empty() {
        return Err(VaultError::Corrupt("trailing bytes in record"));
    }
    Ok(Record {
        session_id,
        generation,
        map,
    })
}

pub(super) fn decode_manifest(plaintext: &[u8]) -> Result<Manifest, VaultError> {
    let mut reader = Reader(plaintext);
    if reader.take(1)?[0] != MANIFEST_VERSION {
        return Err(VaultError::Corrupt("unknown manifest version"));
    }
    let mut generations = BTreeMap::new();
    for _ in 0..reader.u32()? {
        let slot = reader.string()?;
        let generation = reader.u64()?;
        if generations.insert(slot, generation).is_some() {
            return Err(VaultError::Corrupt("duplicate session in manifest"));
        }
    }
    if !reader.0.is_empty() {
        return Err(VaultError::Corrupt("trailing bytes in manifest"));
    }
    Ok(Manifest { generations })
}

/// Bounds-checked cursor over a decrypted record.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8], VaultError> {
        if self.0.len() < len {
            return Err(VaultError::Corrupt("truncated record"));
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, VaultError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, VaultError> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(bytes))
    }

    fn string(&mut self) -> Result<String, VaultError> {
        let len = usize::try_from(self.u32()?)
            .map_err(|_| VaultError::Corrupt("record field too long"))?;
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| VaultError::Corrupt("record text is not UTF-8"))
    }

    fn pairs(&mut self, mut sink: impl FnMut(String, String)) -> Result<(), VaultError> {
        for _ in 0..self.u32()? {
            let token = self.string()?;
            let original = self.string()?;
            sink(token, original);
        }
        Ok(())
    }
}
