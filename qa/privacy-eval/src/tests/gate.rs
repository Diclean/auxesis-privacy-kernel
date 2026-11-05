//! Tests for the gate output checks.

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::EntityKind;

use crate::gate::*;

#[test]
fn a_gate_refusal_is_a_miss() {
    let gold = GoldSpan::new(EntityKind::Secret, 0, 8);
    assert!(!gate_hides("password", &gold, None));
}

/// The split names each hand-made outcome, and a partial mask is `Leaked`
/// because the 6-character run is the only read test the scorer has.
#[test]
fn the_outcome_split_names_masked_leaked_and_blocked() {
    let text = "IBAN FR76 3000 6000 0112 3456 7890 189 ok";
    let gold = GoldSpan::new(EntityKind::Iban, 5, 38);
    assert_eq!(
        outcome(text, &gold, Some("IBAN ⟦IBAN_1⟧ ok")),
        Outcome::Masked
    );
    assert_eq!(outcome(text, &gold, Some(text)), Outcome::Leaked);
    assert_eq!(
        outcome(text, &gold, Some("IBAN ⟦IBAN_1⟧ 7890 189 ok")),
        Outcome::Leaked,
        "a partial mask is folded into leaked"
    );
    assert_eq!(outcome(text, &gold, None), Outcome::Blocked);
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
