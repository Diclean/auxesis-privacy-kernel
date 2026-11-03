//! The stand-in the residue scan uses for a masked token, and the typed
//! look-alike that must not read as one.

use crate::safetext::residue::{clear_parts, MASKED_STAND_IN};

#[test]
fn a_typed_stand_in_is_not_read_as_a_masked_token() {
    // Only a placeholder becomes the stand-in. A U+E000 in the input keeps a
    // different character, so the rescan reads it as text, not as a token.
    assert_eq!(clear_parts("a\u{E000}b"), "a\u{FFFD}b");
    // A stand-in ends its line in the clear text.
    assert_eq!(
        clear_parts("a⟦SECRET_1⟧b"),
        format!("a{MASKED_STAND_IN}\nb")
    );
}
