//! Tests for the decoding and text size caps: an over-cap call asks.

use super::super::*;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};

#[test]
fn a_huge_base64_blob_stays_within_the_cap_and_asks() {
    // About 200 KB of text: its decoded size is over the per-leaf cap, so
    // the screen cannot read it in full and must ask, without decoding it.
    let blob = STANDARD.encode("weather ".repeat(25_000));
    assert_eq!(
        identifier_in_arguments(&json!({ "blob": blob })),
        Some(UNSCREENED_LABEL)
    );
}

#[test]
fn a_clean_base64_blob_under_the_cap_is_allowed() {
    let blob = STANDARD.encode("weather in Paris ".repeat(1_000));
    assert_eq!(identifier_in_arguments(&json!({ "blob": blob })), None);
}

#[test]
fn decoded_views_past_the_call_budget_ask() {
    // Twenty leaves of 80 KB of base64 each: over the text cap, so the call
    // asks before any decoding.
    let leaf = STANDARD.encode("a".repeat(60_000));
    let arguments = Value::Array(vec![json!(leaf); 20]);
    assert_eq!(identifier_in_arguments(&arguments), Some(UNSCREENED_LABEL));
}

#[test]
fn a_call_over_the_text_cap_asks() {
    let arguments = json!({ "body": "weather in Paris ".repeat(20_000) });
    assert_eq!(identifier_in_arguments(&arguments), Some(UNSCREENED_LABEL));
}
