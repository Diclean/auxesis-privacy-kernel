//! Tests for the web egress section and its modes.

use super::super::*;
use tempfile::tempdir;

#[test]
fn web_defaults_are_the_documented_ones() {
    let web = WebConfig::default();
    assert_eq!(web.mode, WebMode::OpenRead);
    assert_eq!(web.mode.as_str(), "open_read");
    assert!(web.allow_domains.is_empty());
    assert!(web.deny_domains.is_empty());
    assert!(!web.https_only);
    assert_eq!(web.port_allowlist, vec![80, 443]);
    assert_eq!(web.max_redirects, 5);
    assert_eq!(web.max_bytes, 262_144);
    assert_eq!(web.timeout_secs, 15);
    assert_eq!(
        web.content_types,
        vec![
            "text/html".to_string(),
            "text/plain".to_string(),
            "application/json".to_string(),
            "application/xml".to_string(),
            "text/xml".to_string(),
        ]
    );
    assert_eq!(web.fetches_per_turn, 8);
    assert_eq!(web.fetches_per_day, 200);
    assert_eq!(web.per_host_per_minute, 10);
    assert_eq!(web.allow_expiry_days, 30);
    assert_eq!(web.max_url_bytes, 512);
    assert_eq!(web.max_query_bytes, 256);
    // A zero timeout keeps the documented default instead of disabling it.
    assert_eq!(
        WebConfig {
            timeout_secs: 0,
            ..WebConfig::default()
        }
        .timeout()
        .as_secs(),
        15
    );
    // The default config carries the safe section and round-trips.
    assert_eq!(Config::default().web, WebConfig::default());
    let text = toml::to_string(&Config::default()).unwrap();
    let reparsed: Config = toml::from_str(&text).unwrap();
    assert_eq!(reparsed, Config::default());
}

#[test]
fn parses_the_web_section() {
    let config: Config = toml::from_str(
        r#"
            version = 1
            [web]
            mode = "always_ask"
            allow_domains = ["docs.rs"]
            deny_domains = ["*.ads.example"]
            https_only = true
            port_allowlist = [443]
            max_redirects = 2
            max_bytes = 1024
            timeout_secs = 3
            content_types = ["text/plain"]
            fetches_per_turn = 1
            fetches_per_day = 2
            per_host_per_minute = 3
            allow_expiry_days = 7
            max_url_bytes = 64
            max_query_bytes = 32
            "#,
    )
    .unwrap();
    let web = config.web;
    assert_eq!(web.mode, WebMode::AlwaysAsk);
    assert_eq!(web.mode.as_str(), "always_ask");
    assert_eq!(web.allow_domains, vec!["docs.rs".to_string()]);
    assert_eq!(web.deny_domains, vec!["*.ads.example".to_string()]);
    assert!(web.https_only);
    assert_eq!(web.port_allowlist, vec![443]);
    assert!(!web.port_allowed(80));
    assert!(web.port_allowed(443));
    assert_eq!(web.max_redirects, 2);
    assert_eq!(web.max_bytes, 1024);
    assert_eq!(web.timeout_secs, 3);
    assert_eq!(web.timeout().as_secs(), 3);
    assert!(web.content_type_allowed("text/plain; charset=utf-8"));
    assert!(!web.content_type_allowed("application/json"));
    assert!(!web.content_type_allowed("text/html"));
    // P3-2: a missing/empty header is not a member of the allowlist.
    assert!(!web.content_type_allowed(""));
    assert!(!web.content_type_allowed("   "));
    // The owner opts in to the sniffer with an explicit empty entry; it
    // allows only the empty header, never another type.
    let sniffer = WebConfig {
        content_types: vec!["text/html".to_string(), String::new()],
        ..WebConfig::default()
    };
    assert!(sniffer.content_type_allowed(""));
    assert!(sniffer.content_type_allowed("text/html"));
    assert!(!sniffer.content_type_allowed("application/json"));
    assert_eq!(web.fetches_per_turn, 1);
    assert_eq!(web.fetches_per_day, 2);
    assert_eq!(web.per_host_per_minute, 3);
    assert_eq!(web.allow_expiry_days, 7);
    assert_eq!(web.max_url_bytes, 64);
    assert_eq!(web.max_query_bytes, 32);
}

#[test]
fn every_documented_mode_parses() {
    for (label, mode) in [
        ("open_read", WebMode::OpenRead),
        ("smart", WebMode::Smart),
        ("ask_once_per_site", WebMode::AskOncePerSite),
        ("always_ask", WebMode::AlwaysAsk),
    ] {
        let config: Config = toml::from_str(&format!("[web]\nmode = \"{label}\"\n")).unwrap();
        assert_eq!(config.web.mode, mode, "{label}");
    }
}

#[test]
fn rejects_unknown_web_mode() {
    // Unknown mode is a config error (fail closed), never a silent
    // fall back to `open_read`.
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[web]\nmode = \"yolo\"\n").unwrap();

    let err = Config::load_or_create(&path).unwrap_err();
    assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
    // The error names the line, never the value (CONFIG-ERR-ECHO-1).
    let message = err.to_string();
    assert!(message.contains("config.toml, line 2"), "{message}");
    assert!(!message.contains("yolo"), "{message}");
}
