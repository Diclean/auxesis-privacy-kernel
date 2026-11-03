//! Value folding and case folding.

use super::*;

#[test]
fn identifier_normalisation_merges_separators_only() {
    assert_eq!(
        normalize_value(EntityKind::Phone, "+33 6 12 34 56 78"),
        normalize_value(EntityKind::Phone, "+33612345678")
    );
    assert_eq!(
        normalize_value(EntityKind::Iban, "fr76 3000 6000 0112 3456 7890 189"),
        normalize_value(EntityKind::Iban, "FR7630006000011234567890189")
    );
    // The leading + is part of the value, so these must not collide.
    assert_ne!(
        normalize_value(EntityKind::Phone, "+33612345678"),
        normalize_value(EntityKind::Phone, "33612345678")
    );
}
#[test]
fn ascii_values_normalise_exactly_as_before() {
    // Golden stability: these inputs keep the same HMAC input as before the
    // Unicode fix, so their tokens do not move.
    assert_eq!(
        normalize_value(EntityKind::Email, "jean.dupont@example.test"),
        "jean.dupont@example.test"
    );
    assert_eq!(
        normalize_value(EntityKind::Phone, "+33 6 12 34 56 78"),
        "+33612345678"
    );
    assert_eq!(
        normalize_value(EntityKind::Iban, "fr76 3000 6000 0112 3456 7890 189"),
        "FR7630006000011234567890189"
    );
    assert_eq!(
        normalize_value(EntityKind::CreditCard, "4242 4242 4242 4242"),
        "4242424242424242"
    );
}
#[test]
fn text_normalisation_keeps_every_letter_and_folds_case() {
    // An accented letter is part of the address: these must not collide.
    assert_ne!(
        normalize_value(EntityKind::Email, "José@example.test"),
        normalize_value(EntityKind::Email, "Jos@example.test")
    );
    assert_eq!(
        normalize_value(EntityKind::Email, "JOSÉ@Example.TEST"),
        normalize_value(EntityKind::Email, "josé@example.test")
    );
    // Full-width forms fold to ASCII under NFKC.
    assert_eq!(
        normalize_value(EntityKind::Email, "ｍａｒｉｅ@example.test"),
        normalize_value(EntityKind::Email, "marie@example.test")
    );
    // CJK letters are kept whole.
    assert_eq!(normalize_value(EntityKind::Person, "田中太郎"), "田中太郎");
    assert_ne!(
        normalize_value(EntityKind::Person, "田中太郎"),
        normalize_value(EntityKind::Person, "田中")
    );
    // Full case folding: ß folds to ss, and the final sigma to σ.
    assert_eq!(casefold("STRAßE"), casefold("Strasse"));
    // Text keys on its exact spelling: a folded spelling is another token.
    assert_ne!(
        normalize_value(EntityKind::Person, "STRAßE"),
        normalize_value(EntityKind::Person, "Strasse")
    );
    assert_eq!(casefold("ΟΔΟΣ"), casefold("οδος"));
    // The dotless ı is its own letter, not an i.
    assert_ne!(
        normalize_value(EntityKind::Person, "ısmail"),
        normalize_value(EntityKind::Person, "ismail")
    );
}
#[test]
fn identifier_normalisation_keeps_letters_and_numerals_of_every_script() {
    // Non-ASCII letters used to vanish, so `ÉA1` and `A1` shared a key.
    assert_ne!(
        normalize_value(EntityKind::NationalId, "ÉA1"),
        normalize_value(EntityKind::NationalId, "A1")
    );
    // A Corsican NIR carries a letter in its department code.
    assert_ne!(
        normalize_value(EntityKind::FrNir, "1 85 2A 123 456 78"),
        normalize_value(EntityKind::FrNir, "1 85 2B 123 456 78")
    );
    // Full-width IBAN letters and digits fold like their ASCII spelling.
    assert_eq!(
        normalize_value(EntityKind::Iban, "ｆｒ76 3000"),
        normalize_value(EntityKind::Iban, "FR763000")
    );
    assert_eq!(
        normalize_value(EntityKind::Phone, "０６ １２ ３４ ５６ ７８"),
        normalize_value(EntityKind::Phone, "0612345678")
    );
    // Non-ASCII digits are kept rather than dropped to an empty key.
    assert_ne!(
        normalize_value(EntityKind::Phone, "٠٦"),
        normalize_value(EntityKind::Phone, "٧٠")
    );
    assert!(!normalize_value(EntityKind::Phone, "٠٦").is_empty());
}
