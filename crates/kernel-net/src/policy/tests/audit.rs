//! Tests for the `web.fetch` audit row.

use kernel_core::WebConfig;

use super::super::audit::sha256_hex;
use super::super::*;
use super::support::web_gate;

#[test]
fn audit_row_logs_host_and_query_hash_never_the_query() {
    let gate = web_gate(WebConfig::default());
    let url = reqwest::Url::parse("https://evil.example/?d=owner-private-notes").unwrap();
    let hash = gate.query_sha256(&url).unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(hash, "owner-private-notes");
    let event = WebFetchEvent {
        host: "evil.example".to_string(),
        query_sha256: Some(hash.clone()),
        url_sha256: None,
        bytes: 0,
        status: "refused".to_string(),
        mode: "open_read".to_string(),
        outcome: "deny:url_too_long".to_string(),
        tainted: true,
        carries_private_data: true,
    };
    let json = event.to_json();
    assert!(json.contains("\"host\":\"evil.example\""));
    assert!(json.contains(&hash));
    assert!(!json.contains("owner-private-notes"), "{json}");
    assert!(json.contains("\"carries_private_data\":true"));
    // A refused redirect hop logs the host and a URL hash, never the URL.
    let secret = reqwest::Url::parse("https://evil.example/log/GRID-SECRET-44000").unwrap();
    let hop = WebFetchEvent {
        host: "evil.example".to_string(),
        query_sha256: None,
        url_sha256: Some(sha256_hex(secret.as_str().as_bytes())),
        bytes: 0,
        status: "redirect_refused".to_string(),
        mode: "open_read".to_string(),
        outcome: "ask:sensitive_turn".to_string(),
        tainted: true,
        carries_private_data: false,
    };
    let hop_json = hop.to_json();
    assert!(hop_json.contains("\"host\":\"evil.example\""));
    assert!(!hop_json.contains("GRID-SECRET-44000"), "{hop_json}");
    assert!(!hop_json.contains("query_sha256"), "{hop_json}");
    // A URL without a query has no query hash.
    assert!(gate
        .query_sha256(&reqwest::Url::parse("https://example.com/path").unwrap())
        .is_none());
}
