//! Tests for bare phone-shaped digit runs, and the epoch exception.

use super::super::phone::phone_shaped_digits;
use super::super::*;

use serde_json::json;

#[test]
fn bare_numbers_shaped_like_phones_ask() {
    // FAKE: phone shapes written as bare digits, none a real line.
    assert!(phone_shaped_digits("12025550142"));
    assert!(phone_shaped_digits("33612345678"));
    assert!(phone_shaped_digits("0612345678"));
    assert!(!phone_shaped_digits("2026"));
    assert!(!phone_shaped_digits("1234567"));
    for arguments in [
        json!(12025550142u64),
        json!("33612345678"),
        json!("0612345678"),
    ] {
        assert_eq!(
            identifier_in_arguments(&arguments),
            Some("a phone number"),
            "{arguments}"
        );
    }
}

#[test]
fn epoch_timestamps_do_not_ask() {
    for arguments in [
        json!({ "created_at": 1760000000 }),
        json!({ "created_at_ms": 1760000000000u64 }),
        json!({ "created_at": 1760000000, "created_at_ms": 1760000000000u64 }),
        json!(["1760000000", "1760000001"]),
        json!({ "since": "1760000000 1760000000000" }),
    ] {
        assert_eq!(identifier_in_arguments(&arguments), None, "{arguments}");
    }
}
