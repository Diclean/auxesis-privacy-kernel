//! Tests for the percent, JSON, hex and base64 decoders.

use super::super::*;
use super::hex;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::json;

#[test]
fn a_percent_encoded_iban_is_found() {
    // FAKE: the specimen FR IBAN, every space percent-encoded.
    let arguments = json!({ "memo": "FR76%203000%206000%200112%203456%207890%20189" });
    assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
}

#[test]
fn a_twice_percent_encoded_iban_is_found() {
    // FAKE: the same specimen, its spaces encoded twice.
    let arguments = json!({ "memo": "FR76%25203000%25206000%25200112%25203456%25207890%2520189" });
    assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
}

#[test]
fn a_base64_encoded_email_is_found() {
    // FAKE: a fictional address, base64-encoded.
    let email = "jean.dupont@example.com";
    let arguments = json!({ "body": STANDARD.encode(email) });
    assert_eq!(
        identifier_in_arguments(&arguments),
        Some("an e-mail address")
    );
}

#[test]
fn a_url_safe_base64_encoded_email_is_found() {
    // FAKE: the payload's standard base64 has a `/`, so its URL-safe form
    // carries a `_` and only the URL-safe decoder reads it back.
    let payload = "jean.dupont@example.com ???";
    let encoded = URL_SAFE_NO_PAD.encode(payload);
    assert!(encoded.contains('_'), "{encoded}");
    let arguments = json!({ "body": encoded });
    assert_eq!(
        identifier_in_arguments(&arguments),
        Some("an e-mail address")
    );
}

#[test]
fn a_hex_encoded_iban_is_found() {
    // FAKE: the specimen FR IBAN, hex-encoded.
    let arguments = json!({ "blob": hex("FR76 3000 6000 0112 3456 7890 189") });
    assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
}

#[test]
fn a_json_unicode_escaped_iban_is_found() {
    // FAKE: the specimen FR IBAN, its `F` carried as a literal JSON escape.
    let arguments = json!({ "memo": r"FR76 3000 6000 0112 3456 7890 189" });
    assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
}

#[test]
fn malformed_encodings_are_ignored() {
    let arguments = json!({
        "percent": "%zz%4",
        "padding": "================",
        "symbols": "@@@@@@@@@@@@@@@@@@@@",
        "bytes": "%E9%FF%C3",
        "base64": "ABCDEFGHIJKLMNOPQRS=",
        "hex": "zzzzzzzzzzzzzzzzzzzz"
    });
    assert_eq!(identifier_in_arguments(&arguments), None);
}
