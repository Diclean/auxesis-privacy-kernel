//! Tests for the gate's URL-shape checks and the permissive test gate.

use kernel_core::WebConfig;

use super::super::*;
use super::support::web_gate;

#[test]
fn domain_matching_is_suffix_scoped() {
    assert!(domain_matches("docs.rs", "docs.rs"));
    assert!(domain_matches("docs.rs", "a.docs.rs"));
    assert!(domain_matches("*.ads.example", "ads.example"));
    assert!(domain_matches("*.ads.example", "x.ads.example"));
    assert!(domain_matches(".example.com", "example.com"));
    assert!(!domain_matches("example.com", "notexample.com"));
    assert!(!domain_matches("example.com", "example.com.evil"));
    assert!(!domain_matches("", "example.com"));
    assert!(domain_matches("DOCS.RS", "docs.rs"));
}

#[test]
fn gate_refuses_url_shapes_before_any_network() {
    let default = web_gate(WebConfig::default());
    assert_eq!(
        default.check("ftp://example.com/x").unwrap_err(),
        DenyReason::NotHttp
    );
    assert_eq!(
        default.check("file:///etc/passwd").unwrap_err(),
        DenyReason::NotHttp
    );
    assert_eq!(
        web_gate(WebConfig {
            https_only: true,
            ..WebConfig::default()
        })
        .check("http://example.com/")
        .unwrap_err(),
        DenyReason::HttpsOnly
    );
    assert_eq!(
        default.check("https://example.com:8080/").unwrap_err(),
        DenyReason::PortNotAllowed
    );
    assert!(default.check("https://example.com/").is_ok());
    assert!(default.check("http://example.com/").is_ok());
}

#[test]
fn gate_refuses_ip_and_obfuscated_hosts() {
    let default = web_gate(WebConfig::default());
    // A bare IP literal is refused outright.
    for url in ["https://8.8.8.8/", "https://[2606:4700::1111]/"] {
        assert_eq!(
            default.check(url).unwrap_err(),
            DenyReason::IpLiteral,
            "{url}"
        );
    }
    // Numeric smuggling spellings are refused whatever their exact
    // classification: Rust's IPv4 parser already accepts several of them
    // (single integer, `0x`-prefixed, short forms), the rest are caught as
    // obfuscated hosts. `256.1.1.1` is out of range, so it is not an
    // address and the shape check is what refuses it.
    for url in [
        "https://2130706433/",
        "https://0177.0.0.1/",
        "https://127.1/",
        "https://0x7f.1/",
    ] {
        assert!(default.check(url).is_err(), "{url} must be refused");
    }
    assert_eq!(
        default.check_host_shape("1.2.3.999").unwrap_err(),
        DenyReason::ObfuscatedHost
    );
    assert_eq!(
        default.check_host_shape("xn--g00gle-9db.com").unwrap_err(),
        DenyReason::PunycodeHost
    );
}

#[test]
fn url_and_query_caps_refuse_never_truncate() {
    let url_gate = web_gate(WebConfig {
        max_url_bytes: 32,
        ..WebConfig::default()
    });
    assert_eq!(
        url_gate
            .check("https://example.com/aaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap_err(),
        DenyReason::UrlTooLong
    );
    let query_gate = web_gate(WebConfig {
        max_url_bytes: 256,
        max_query_bytes: 8,
        ..WebConfig::default()
    });
    assert_eq!(
        query_gate
            .check("https://example.com/?q=0123456789")
            .unwrap_err(),
        DenyReason::QueryTooLong
    );
}

#[test]
fn wb_unparseable_input_is_refused_as_not_http() {
    let gate = web_gate(WebConfig::default());
    assert_eq!(gate.check("not a url").unwrap_err(), DenyReason::NotHttp);
    assert_eq!(gate.check("https://").unwrap_err(), DenyReason::NotHttp);
}

#[test]
fn wb_numeric_spellings_are_ip_literals_after_url_normalisation() {
    // The url crate parses these hosts as IPv4 (WHATWG rules) before the
    // gate sees them, so the shape check classifies them as IpLiteral.
    let gate = web_gate(WebConfig::default());
    for url in [
        "https://2130706433/",
        "https://0177.0.0.1/",
        "https://127.1/",
        "https://0x7f.1/",
    ] {
        assert_eq!(gate.check(url).unwrap_err(), DenyReason::IpLiteral, "{url}");
    }
}

#[test]
#[ignore = "KNET-WB-1: check_host_shape misses the dotless integer spelling `2130706433` (is_obfuscated_numeric_host requires a `.`); today only the url-crate normalisation in check() catches it — see PR"]
fn wb_dotless_integer_host_shape_is_refused() {
    let gate = web_gate(WebConfig::default());
    assert_eq!(
        gate.check_host_shape("2130706433").unwrap_err(),
        DenyReason::ObfuscatedHost
    );
}

#[test]
fn wb_no_known_port_is_not_http() {
    let gate = web_gate(WebConfig::default());
    // A non-special scheme has no known default port; refused before any DNS.
    let url = reqwest::Url::parse("foo://example.com/").unwrap();
    assert!(url.port_or_known_default().is_none());
    assert_eq!(
        gate.check_after_resolve(&url).unwrap_err(),
        DenyReason::NotHttp
    );
}

#[test]
fn wb_empty_host_shape_is_not_http() {
    let gate = web_gate(WebConfig::default());
    assert_eq!(gate.check_host_shape("").unwrap_err(), DenyReason::NotHttp);
}

#[test]
fn wb_host_of_text_hash_and_mode_label_support_the_audit_row() {
    let gate = web_gate(WebConfig {
        mode: kernel_core::WebMode::AlwaysAsk,
        ..WebConfig::default()
    });
    assert_eq!(
        gate.host_of("https://Example.COM/x"),
        Some("example.com".to_string())
    );
    assert_eq!(gate.host_of("not a url"), None);
    assert_eq!(gate.mode_label(), "always_ask");
    let hash = gate.text_sha256("owner-private-notes");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(hash, "owner-private-notes");
}

#[test]
fn permissive_test_gate_allows_loopback_but_keeps_deny_and_caps() {
    let gate = WebGate::permissive_for_tests(WebConfig {
        deny_domains: vec!["bad.example".to_string()],
        max_url_bytes: 40,
        ..WebConfig::default()
    });
    assert!(gate.check("http://127.0.0.1:51234/page").is_ok());
    assert_eq!(
        gate.check("https://bad.example/").unwrap_err(),
        DenyReason::DeniedDomain
    );
    assert_eq!(
        gate.check("https://example.com/aaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap_err(),
        DenyReason::UrlTooLong
    );
}
