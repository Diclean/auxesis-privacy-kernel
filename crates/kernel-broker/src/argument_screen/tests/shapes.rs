//! Tests for opaque identifier shapes: UUID, git SHA, digest, ULID, Calendar and
//! Drive IDs never ask.

use super::super::encoded::looks_encoded_token;
use super::super::*;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::json;

#[test]
fn a_uuid_shape_is_never_a_residue() {
    assert!(!looks_encoded_token("550e8400-e29b-41d4-a716-446655440000"));
    assert!(!looks_encoded_token("550e8400e29b41d4a716446655440000"));
    assert!(looks_encoded_token("550e8400e29b41d4a716446655440001ff"));
}

#[test]
fn a_sha256_or_sha512_digest_is_never_a_residue() {
    // FAKE: a real SHA-256 digest (of the empty input), and a 128-digit run
    // of its doubled hex in the SHA-512 shape.
    let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let sha512 = format!("{sha256}{sha256}");
    assert!(!looks_encoded_token(sha256));
    assert!(!looks_encoded_token(&sha512));
    // One digit past the shape is no digest: an ordinary hex run, so it asks.
    assert!(looks_encoded_token(&format!("{sha512}f")));
}

#[test]
fn ordinary_text_urls_uuids_and_short_hashes_do_not_ask() {
    // FAKE: a real SHA-256 digest (of the empty input) and its doubled hex.
    let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let sha512 = format!("{sha256}{sha256}");
    // Each value alone, collecting every hit.
    let mut asked = Vec::new();
    for value in [
        "weather in Paris",
        "https://example.com/docs/getting-started/installation-guide",
        "9f86d081884c7d65",
        "550e8400-e29b-41d4-a716-446655440000",
        "550e8400e29b41d4a716446655440000",
        sha256,
        sha512.as_str(),
    ] {
        if let Some(label) = identifier_in_arguments(&json!(value)) {
            asked.push(format!("{value}: {label}"));
        }
    }
    assert!(asked.is_empty(), "{asked:?}");
    let arguments = json!({
        "query": "weather in Paris",
        "url": "https://example.com/docs/getting-started/installation-guide",
        "hash": "9f86d081884c7d65",
        "digest": sha256,
        "limit": 5
    });
    assert_eq!(identifier_in_arguments(&arguments), None);
}

#[test]
fn opaque_identifiers_do_not_ask() {
    // FAKE: opaque IDs of each known shape. A Calendar event ID, a Drive file
    // ID (its base64 decoding is not text), a UUID, a ULID and a git SHA.
    let shapes = [
        "3pr8bd9ti1b2g0s6ch5o6r1s7k",
        "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms",
        "550e8400-e29b-41d4-a716-446655440000",
        "550e8400e29b41d4a716446655440000",
        "01HZX3K5M8T2W9YQ4N6P7R8S9V",
        "0a80bacac0aff8cdc04c4d3bc56378b7cacc5998",
    ];
    for value in shapes {
        assert_eq!(identifier_in_arguments(&json!(value)), None, "{value}");
    }
    // All of them in one call, a UUID directly followed by a ULID included.
    let arguments = json!({
        "eventId": shapes[0],
        "fileId": shapes[1],
        "requestId": shapes[2],
        "bareRequestId": shapes[3],
        "ulid": shapes[4],
        "commit": shapes[5],
        "keys": [shapes[2], shapes[4]],
        "shaKey": { "0a80bacac0aff8cdc04c4d3bc56378b7cacc5998": 1 }
    });
    assert_eq!(identifier_in_arguments(&arguments), None);
}

#[test]
fn near_misses_of_the_opaque_shapes_still_ask() {
    // Encoded text is still encoded, whatever its shape.
    let email = STANDARD.encode("jean.dupont@example.com");
    assert!(looks_encoded_token(&email));
    assert!(identifier_in_arguments(&json!({ "blob": email })).is_some());
    // A UUID is exempt as a whole token only: a phone glued to one still asks.
    assert_eq!(
        identifier_in_arguments(&json!("0612345678-550e8400-e29b-41d4-a716-446655440000")),
        Some("a phone number")
    );
    // A UK number split with a leading one: the epoch rule covers one value,
    // not the join of two.
    assert_eq!(
        identifier_in_arguments(&json!({ "numbers": ["44", "1234567890"] })),
        Some("a phone number")
    );
    // A US national number opens with 2, never 1, and stays a phone.
    assert_eq!(
        identifier_in_arguments(&json!("2125550142")),
        Some("a phone number")
    );
    // A valid IBAN is never a false hit, bare or glued to a letter, even though
    // its token has the shape of a Drive file ID.
    // FAKE: the checksum-valid specimen FR IBAN, compact.
    assert_eq!(
        identifier_in_arguments(&json!("FR7630006000011234567890189")),
        Some("an IBAN")
    );
    assert!(identifier_in_arguments(&json!("xFR7630006000011234567890189")).is_some());
}
