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
    // The dotless integer spelling is NOT caught here (no `.`): through
    // `WebGate::check` the URL parser normalises it to an IPv4 literal
    // first. The shape-check gap on the raw spelling is KNET-WB-1.
    assert!(!is_obfuscated_numeric_host("2130706433"));
}
