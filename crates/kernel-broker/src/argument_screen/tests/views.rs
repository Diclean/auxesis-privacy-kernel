//! Tests for the joined views, including an identifier split across fields.

use super::super::views::digits_and_letters;
use super::super::*;

use serde_json::json;

#[test]
fn an_iban_split_over_two_fields_is_found() {
    // FAKE: the specimen FR IBAN, split over two sibling fields.
    let arguments = json!({ "a": "FR76 3000", "b": "6000 0112 3456 7890 189" });
    assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
}

#[test]
fn an_iban_split_across_nested_arrays_and_objects_is_found() {
    // FAKE: the specimen FR IBAN, split across two nested branches.
    let arguments = json!({
        "items": [
            { "p": "FR76 3000" },
            { "q": { "r": ["6000 0112 3456 7890 189"] } }
        ]
    });
    assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
}

#[test]
fn an_iban_split_across_three_fields_with_text_between_asks() {
    // FAKE: the specimen FR IBAN, split over three fields, a text field between.
    let arguments = json!({
        "a": "FR76 3000",
        "b": "Virement loyer",
        "c": "6000 0112 3456 7890 189"
    });
    // Another recogniser may name it first (grouped digits read as a phone);
    // the call must still ask.
    assert!(identifier_in_arguments(&arguments).is_some());
}

#[test]
fn the_digits_view_joins_the_split_fields_and_skips_the_text() {
    // FAKE: the specimen FR IBAN, split with a text field between.
    let leaves = vec![
        "FR76 3000".to_string(),
        "Virement loyer".to_string(),
        "6000 0112 3456 7890 189".to_string(),
    ];
    assert_eq!(digits_and_letters(&leaves), "FR7630006000011234567890189");
}

#[test]
fn a_phone_split_across_an_array_with_text_between_asks() {
    // FAKE: a phone number split over an array, a text item between its parts.
    let arguments = json!({ "numbers": ["33", "Bonjour", "612345678"] });
    assert!(identifier_in_arguments(&arguments).is_some());
}
