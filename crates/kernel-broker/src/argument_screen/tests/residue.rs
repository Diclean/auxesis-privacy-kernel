//! Tests for residue detection: a decoding chain that stops while it still looks
//! encoded asks.

use super::super::*;
use super::{hex, percent_layers};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::json;

#[test]
fn a_triply_encoded_email_asks() {
    // FAKE: a fictional address, base64-encoded three times over.
    let email = "jean.dupont@example.com";
    let triple = STANDARD.encode(STANDARD.encode(STANDARD.encode(email)));
    assert_eq!(
        identifier_in_arguments(&json!({ "body": triple })),
        Some(RESIDUE_LABEL)
    );
}

#[test]
fn a_triply_percent_encoded_text_asks_on_residue() {
    // Plain text, every space percent-encoded three times: no recogniser
    // fires, so the residue rule is what asks.
    let triple = "weather in Paris".replace(' ', "%252520");
    assert_eq!(
        identifier_in_arguments(&json!({ "memo": triple })),
        Some(RESIDUE_LABEL)
    );
}

#[test]
fn a_triply_percent_encoded_iban_asks() {
    // FAKE: the specimen FR IBAN, every space percent-encoded three times.
    // Another hit may name it first; the call must still ask.
    let triple = "FR76 3000 6000 0112 3456 7890 189".replace(' ', "%252520");
    assert!(identifier_in_arguments(&json!({ "memo": triple })).is_some());
}

#[test]
fn an_encoded_token_inside_a_sentence_asks() {
    // A base64 token inside a sentence is never decoded, so it asks.
    let arguments = json!({ "memo": "voici SGVsbG8gV29ybGQgdGhpcyBpcyBiYXNlNjQ= merci" });
    assert!(identifier_in_arguments(&arguments).is_some());
}

#[test]
fn a_stray_json_unicode_escape_asks() {
    // The malformed escape is left as written after decoding, so it asks.
    let arguments = json!({ "escape": "\\uD83D\\u00" });
    assert_eq!(identifier_in_arguments(&arguments), Some(RESIDUE_LABEL));
}

#[test]
fn a_triply_encoded_at_sign_under_the_escape_share_asks() {
    // FAKE: a fictional address, its `@` percent-encoded three times. After
    // the two rounds the screen reads, one `%40` is left: 3 of 20 bytes.
    let arguments = json!({ "memo": "q7f3k9%252540example.com" });
    assert_eq!(identifier_in_arguments(&arguments), Some(RESIDUE_LABEL));
}

#[test]
fn deeply_encoded_emails_and_phones_ask() {
    // FAKE: a fictional address and a fictional French mobile number.
    for layers in [4, 6] {
        for value in [
            percent_layers("q7f3k9@example.com", layers),
            percent_layers("+33 6 12 34 56 78", layers),
            format!("{}33612345678", percent_layers("+", layers)),
            format!("q7f3k9{}example.com", percent_layers("@", layers)),
        ] {
            assert!(
                identifier_in_arguments(&json!({ "memo": value })).is_some(),
                "{layers} layers: {value}"
            );
        }
    }
}

#[test]
fn a_short_hex_layer_left_at_the_cap_asks() {
    // FAKE: a fictional address, hex-encoded three times. The layer left at
    // the cap is 18 hex digits: shorter than a hex run, but it still decodes.
    let triple = hex(&hex(&hex("q7@ex.com")));
    assert_eq!(
        identifier_in_arguments(&json!({ "blob": triple })),
        Some(RESIDUE_LABEL)
    );
}

#[test]
fn plain_urls_with_ordinary_escapes_still_pass() {
    for url in [
        "https://example.com/search?q=weather%20in%20Paris",
        "https://example.com/search?q=weather%2520in%2520Paris",
        "https://example.com/a%2Fb?city=Saint-%C3%89tienne&n=5",
    ] {
        assert_eq!(
            identifier_in_arguments(&json!({ "url": url })),
            None,
            "{url}"
        );
    }
}

#[test]
fn long_snake_case_keys_do_not_ask() {
    let arguments = json!({
        "calendar_event_attendee_response_status": "accepted",
        "calendar_event_organizer_display_name_fallback": "Équipe produit",
        "max_results": 10
    });
    assert_eq!(identifier_in_arguments(&arguments), None);
    assert_eq!(
        identifier_in_arguments(&json!("calendar_event_attendee_response_status")),
        None
    );
}
