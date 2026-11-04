//! Tests for the host helpers: domain matching and obfuscated numeric shapes.

use super::super::host::is_obfuscated_numeric_host;
use super::super::*;

#[test]
fn wb_domain_matches_trims_case_and_trailing_dots() {
    assert!(domain_matches(" Example.COM. ", "example.com"));
    assert!(domain_matches("example.com.", "EXAMPLE.com."));
    assert!(domain_matches("*.example.com", "example.com"));
    assert!(!domain_matches("example.com", ""));
    assert!(!domain_matches("", "example.com"));
}

#[test]
fn wb_wildcard_alone_matches_nothing() {
    // `*.` and `.` alone strip to an empty suffix, which matches no host.
    assert!(!domain_matches("*.", "anything.example"));
    assert!(!domain_matches(".", "anything.example"));
}

#[test]
fn wb_obfuscated_numeric_host_spellings() {
    assert!(!is_obfuscated_numeric_host(""));
    assert!(!is_obfuscated_numeric_host("example.com"));
    // Any dotted-numeric string is flagged here, valid literal included;
    // the gate orders the IpAddr parse first, so valid literals surface as
    // IpLiteral there, not as ObfuscatedHost.
    assert!(is_obfuscated_numeric_host("1.2.3.4"));
    assert!(is_obfuscated_numeric_host("0x7f.1"));
    assert!(is_obfuscated_numeric_host("0x7f000001"));
    assert!(is_obfuscated_numeric_host("0177.0.0.1"));
    assert!(is_obfuscated_numeric_host("127.1"));
    // A dotless all-digit spelling is refused here directly: it no longer
    // relies on the URL parser normalising it to an IPv4 literal first.
    assert!(is_obfuscated_numeric_host("2130706433"));
    assert!(is_obfuscated_numeric_host("017700000001"));
    // Names that merely contain digits are not numeric spellings.
    for host in ["123.example", "web1.example.com", "a1b2.example"] {
        assert!(!is_obfuscated_numeric_host(host), "{host}");
    }
}
