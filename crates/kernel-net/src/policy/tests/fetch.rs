//! Tests for `FetchEgress`: the per-call approval authority behind
//! `DenyReason::OriginNotApproved` and `FetchError::RedirectNeedsApproval`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use super::super::*;

fn egress(approved: &[&str]) -> FetchEgress {
    FetchEgress {
        context: EgressContext::default(),
        seen_origins: Arc::new(BTreeSet::new()),
        approved_origins: Arc::new(
            approved
                .iter()
                .map(|origin| (*origin).to_string())
                .collect(),
        ),
        budget: Arc::new(Mutex::new(WebBudget::new())),
        refused_hops: Arc::new(Mutex::new(Vec::new())),
        received_response: Arc::new(Mutex::new(false)),
        received_origins: Arc::new(Mutex::new(BTreeMap::new())),
    }
}

#[test]
fn wb_approves_matches_the_exact_origin_tuple() {
    let egress = egress(&["https://example.com:443"]);
    let url = |input: &str| reqwest::Url::parse(input).unwrap();
    assert!(egress.approves(&url("https://example.com/")));
    assert!(egress.approves(&url("https://example.com/deep/path?q=1")));
    // Different scheme, port or host — including a subdomain — is another origin.
    assert!(!egress.approves(&url("http://example.com/")));
    assert!(!egress.approves(&url("https://example.com:8443/")));
    assert!(!egress.approves(&url("https://sub.example.com/")));
    assert!(!egress.approves(&url("https://other.example/")));
}

#[test]
fn wb_received_response_flag_starts_false() {
    let egress = egress(&[]);
    assert!(!egress.received_response());
    egress.note_received_response();
    assert!(egress.received_response());
}

#[test]
fn wb_note_origin_response_records_status_per_origin() {
    let egress = egress(&[]);
    assert_eq!(egress.origin_receipt("https://example.com:443"), None);
    egress.note_origin_response("https://example.com/a", 200);
    egress.note_origin_response("https://example.com/b", 404);
    assert_eq!(
        egress.origin_receipt("https://example.com:443"),
        Some(OriginReceipt {
            http_status: 404,
            bytes: 0
        })
    );
    assert!(egress.received_response());
    // An unparseable URL still marks "a server answered" but records no origin.
    egress.note_origin_response("not a url", 500);
    assert_eq!(egress.origin_receipt(""), None);
}

#[test]
fn wb_note_origin_bytes_accumulates_per_origin() {
    let egress = egress(&[]);
    egress.note_origin_bytes("https://example.com/a", 100);
    egress.note_origin_bytes("https://example.com/b", 23);
    egress.note_origin_bytes("https://other.example/", 7);
    assert_eq!(
        egress.origin_receipt("https://example.com:443"),
        Some(OriginReceipt {
            http_status: 0,
            bytes: 123
        })
    );
    assert_eq!(
        egress.origin_receipt("https://other.example:443"),
        Some(OriginReceipt {
            http_status: 0,
            bytes: 7
        })
    );
}

#[test]
fn wb_note_refused_hop_records_host_and_url_hash_never_the_url() {
    let egress = egress(&[]);
    let secret = "https://evil.example/log/GRID-SECRET-44000?d=1";
    egress.note_refused_hop(secret);
    // An unparseable hop still gets a row, with an empty host.
    egress.note_refused_hop("not a url");
    let hops = egress.take_refused_hops();
    assert_eq!(hops.len(), 2);
    assert_eq!(hops[0].host, "evil.example");
    assert_eq!(hops[0].url_sha256.len(), 64);
    assert!(hops[0].url_sha256.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(hops[0].url_sha256, secret);
    assert!(!hops[0].url_sha256.contains("GRID-SECRET-44000"));
    assert_eq!(hops[1].host, "");
    // take drains: a second take is empty.
    assert!(egress.take_refused_hops().is_empty());
}
