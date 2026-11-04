//! Tests for the eval harness, split by topic.

mod cases;
mod classes;
mod gate;
mod heldout;
mod table;
mod tier_c;
mod tiers;

#[test]
fn old_version_vector_eval_hash() {
    assert_eq!(
        crate::sha256_hex(b"synthetic\n"),
        "18c4f85a180cf29ddc1f8e3a3143ff54d643d1c306dbe610f4f70482632071d4"
    );
}
