//! Tests for the redacted TOML parse errors.

use super::super::*;
use tempfile::tempdir;

#[test]
fn a_broken_line_with_a_key_never_reaches_the_parse_error() {
    // CONFIG-ERR-ECHO-1: a key pasted on a broken line or as a bad value
    // names the file and line, never the text.
    for text in [
        "log_level = \"info\"\napi_key = \"sk-CANARY-1234567890abcdef\n",
        "log_level = \"info\"\nturn_timeout_secs = \"CANARY-1234567890abcdef\"\n",
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, text).unwrap();
        let err = Config::load_or_create(&path).unwrap_err();
        let (shown, debug) = (err.to_string(), format!("{err:?}"));
        assert!(
            !shown.contains("CANARY") && !debug.contains("CANARY"),
            "{debug}"
        );
        assert!(shown.contains("config.toml, line 2"), "{shown}");
    }
}

#[test]
fn a_redacted_error_keeps_only_a_fixed_kind() {
    let text = "a = 1\nb = [1, 2\n";
    let err = toml::from_str::<toml::Value>(text).unwrap_err();
    let shown = redact_toml_error(&err, "x.toml", text)
        .message()
        .to_string();
    assert!(shown.starts_with("x.toml, line 2, column "), "{shown}");
    assert!(shown.ends_with(": syntax error"), "{shown}");
}

#[test]
fn an_unknown_variant_or_bad_value_names_only_a_kind() {
    // serde quotes the variant, the value and the field name it read.
    for (text, kind) in [
        ("approvals = \"sk-abc\"\n", "unknown value"),
        ("[web]\nmode = \"sk-abc\"\n", "unknown value"),
        ("turn_timeout_secs = \"sk-abc\"\n", "wrong type"),
        ("log_level = \"sk-abc\"\n", "invalid log_level"),
        ("[brief]\ntime = \"sk-abc\"\n", "invalid local time"),
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, text).unwrap();
        let err = Config::load_or_create(&path).unwrap_err();
        let (shown, debug) = (err.to_string(), format!("{err:?}"));
        assert!(!shown.contains("abc") && !debug.contains("abc"), "{debug}");
        assert!(shown.contains(kind), "{shown}");
    }
}
