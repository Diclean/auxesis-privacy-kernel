//! Tests for the screen's entry point and its ordinary-argument paths.

use super::super::*;
use super::hex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::json;

#[test]
fn a_fake_iban_in_a_nested_argument_is_found() {
    // FAKE: the checksum-valid specimen FR IBAN used across the tests.
    let arguments = json!({
        "query": "virement",
        "payee": { "memo": "FR76 3000 6000 0112 3456 7890 189" }
    });
    assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
}

#[test]
fn an_iban_wrapped_over_a_json_newline_is_found() {
    // The newline is a real character in the value; the screen scans the
    // value, not its `\n` escape.
    let arguments = json!({ "memo": "FR76 3000 6000 0112 3456\n7890 189" });
    assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
}

#[test]
fn ordinary_arguments_and_urls_are_not_identifiers() {
    let arguments = json!({
        "query": "weather in Paris",
        "limit": 5,
        "url": "https://example.com/page",
        "host": "10.0.0.5"
    });
    assert_eq!(identifier_in_arguments(&arguments), None);
}

#[test]
fn a_clean_encoded_call_is_still_allowed() {
    // Each encoded field on its own, so a hit names the field that trips it.
    for field in [
        STANDARD.encode("weather in Paris"),
        "weather%20in%20Paris".to_string(),
        hex("fox jumps"),
        r"weather in Paris".to_string(),
    ] {
        assert_eq!(identifier_in_arguments(&json!(field)), None, "{field}");
    }
    let arguments = json!({
        "query": STANDARD.encode("weather in Paris"),
        "memo": "weather%20in%20Paris",
        "blob": hex("fox jumps"),
        "page": r"weather in Paris"
    });
    assert_eq!(identifier_in_arguments(&arguments), None);
}

#[test]
fn nested_arrays_and_objects_are_walked() {
    // FAKE: the specimen FR IBAN buried in arrays and objects.
    let arguments = json!({
        "items": [ { "deep": { "list": ["FR76 3000 6000 0112 3456 7890 189"] } } ]
    });
    assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
}

#[test]
fn years_and_short_ids_do_not_ask() {
    for arguments in [json!(2026), json!(1234567), json!({ "page": 2 })] {
        assert_eq!(identifier_in_arguments(&arguments), None, "{arguments}");
    }
}
