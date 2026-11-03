//! Tests for the gate output checks.

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::EntityKind;

use crate::gate::*;

#[test]
fn a_gate_refusal_is_a_miss() {
    let gold = GoldSpan::new(EntityKind::Secret, 0, 8);
    assert!(!gate_hides("password", &gold, None));
}

/// A value is hidden only when no run of 6 of its letters and digits is
/// left: a half-masked IBAN is a miss, a fully tokenised one is not.
#[test]
fn a_partial_mask_is_a_miss() {
    let text = "IBAN FR76 3000 6000 0112 3456 7890 189 ok";
    let gold = GoldSpan::new(EntityKind::Iban, 5, 38);
    assert!(leaked(text, &gold, "IBAN ⟦IBAN_1⟧ 7890 189 ok"));
    assert!(!leaked(text, &gold, "IBAN ⟦IBAN_1⟧ ok"));
    assert!(!leaked(text, &gold, "IBAN [IBAN removed] ok"));
}
