//! The tagged, length-prefixed encoding shared by the keyed MCP digests.
//!
//! Every field carries a tag and a length (or a count), so no two shapes can
//! serialise to the same byte stream. The approval and the confirmation
//! digests both use it, so a field can never be read as another field's tag,
//! as an item of another list, or as the next field.

/// Feed one tagged, length-prefixed field into a digest.
///
/// The tag names the field and the length makes the encoding prefix-free, so a
/// value can never be read as another field's tag, as an item of another list,
/// or as the next field.
pub(super) fn hash_field(hasher: &mut blake3::Hasher, tag: &[u8], value: &str) {
    hasher.update(tag);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

/// Feed one tagged list count into a digest, before the tagged items.
pub(super) fn hash_count(hasher: &mut blake3::Hasher, tag: &[u8], count: usize) {
    hasher.update(tag);
    hasher.update(&(count as u64).to_le_bytes());
}

/// Feed one tagged boolean into a digest.
pub(super) fn hash_flag(hasher: &mut blake3::Hasher, tag: &[u8], value: bool) {
    hasher.update(tag);
    hasher.update(&[u8::from(value)]);
}
