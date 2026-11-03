//! The shared redaction canaries, plus the end-to-end checks that the layer
//! redacts a value with no credential name in front of it.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    mod redaction_canaries {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/redaction_canaries.rs"
        ));
    }

    #[test]
    fn shared_secret_redaction_canaries_are_removed_from_registered_values() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        for canary in redaction_canaries::CANARIES {
            register_known_secret(canary.secret);
        }
        redaction_canaries::assert_no_canaries(|text| {
            redact_known_secrets(text).unwrap_or_else(|| text.to_string())
        });
        clear_known_secrets();
    }

    #[test]
    fn known_values_are_redacted_without_any_name_in_front() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("PLAIN");
        assert!(register_known_secret(&secret));
        let raw = format!("please use {secret} to sign in");
        let clean = redact_known_secrets(&raw).expect("known value must match");
        assert!(!clean.contains(&secret), "{clean}");
        assert!(clean.contains("<redacted>"), "{clean}");
        // The shared entry point runs the layer first, so this is redacted
        // even though no heuristic rule can see a value with no name.
        let shared = crate::text::redact_secrets(&raw);
        assert!(!shared.contains(&secret), "{shared}");
        // Unrelated text stays `None` (the layer allocates nothing).
        assert!(redact_known_secrets("an ordinary sentence").is_none());
        let accented = format!("é{secret}");
        assert!(register_known_secret(&accented));
        assert!(redact_known_secrets("literal \\xE9, \\n, and é in docs").is_none());
        let large = format!("é{}\\n\\xE9", "z".repeat(4 * 1024 * 1024));
        assert!(redact_known_secrets(&large).is_none());
        let invalid = format!("{}\\n\\m", "z".repeat(4 * 1024 * 1024));
        assert!(redact_known_secrets(&invalid).is_none());
        let text = format!("before \\xE9{secret} after");
        assert!(redact_known_secrets(&text).as_deref() == Some("before <redacted> after"));
        clear_known_secrets();
    }

    #[test]
    fn secrets_in_json_keys_are_redacted_by_the_tree_walker() {
        // E6-02: `scrub_json_value` only walked values, so a secret used as a
        // JSON *key* survived the activity/WS summary path.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("JSONKEY");
        assert!(register_known_secret(&secret));
        let mut value: serde_json::Value =
            serde_json::from_str(&format!(r#"{{"{secret}":"owner","keep":"x"}}"#)).unwrap();
        crate::text::scrub_json_value(&mut value);
        let serialised = value.to_string();
        assert!(!serialised.contains(&secret), "{serialised}");
        assert!(serialised.contains(MASK), "{serialised}");
        // The raw text path already saw the key; keep it pinned too.
        let clean = crate::text::redact_secrets(&format!(r#"{{"{secret}":"owner"}}"#));
        assert!(!clean.contains(&secret), "{clean}");
        clear_known_secrets();
    }
}
