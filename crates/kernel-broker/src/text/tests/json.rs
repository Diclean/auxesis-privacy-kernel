//! Tests for structured JSON redaction and its byte-preserving clean paths.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_value_trees_are_scrubbed_before_serialisation() {
        // The activity/WS summary path holds a `Value` before it becomes a
        // string (B3-02): the walker must mask credential keys and recurse
        // into JSON hidden inside string values.
        let mut value: serde_json::Value = serde_json::from_str(
            "{\"api_key\":\"CANARYJSONKEY0001\",\"agent\":\"main\",\"nested\":{\"token\":\"CANARY_E3E_NEST06\"},\"detail\":\"{\\\"password\\\":\\\"CANARY_E3E_ESCQ03\\\"}\",\"id\":1699999999999}",
        )
        .unwrap();
        scrub_json_value(&mut value);
        let serialised = serde_json::to_string(&value).unwrap();
        for secret in [
            "CANARYJSONKEY0001",
            "CANARY_E3E_NEST06",
            "CANARY_E3E_ESCQ03",
        ] {
            assert!(
                !serialised.contains(secret),
                "leaked {secret}: {serialised}"
            );
        }
        assert!(serialised.contains("<redacted>"), "{serialised}");
        // A false positive survives the walk.
        let mut fp: serde_json::Value =
            serde_json::from_str("{\"token\":\"abc\",\"token_id\":\"abc\"}").unwrap();
        scrub_json_value(&mut fp);
        assert_eq!(fp.to_string(), "{\"token\":\"abc\",\"token_id\":\"abc\"}");
        // M09 pin (round-5 mutation survived): a container under a strong
        // key is masked whole; nothing asserted this before.
        let mut containers: serde_json::Value =
            serde_json::from_str(r#"{"api_key":["a","b"],"deep":{"password":{"x":1}}}"#).unwrap();
        scrub_json_value(&mut containers);
        assert_eq!(
            containers.to_string(),
            r#"{"api_key":"<redacted>","deep":{"password":"<redacted>"}}"#
        );
        // E5-01 through the tree walk (the activity/WS summary path).
        let mut siblings: serde_json::Value =
            serde_json::from_str(r#"{"detail":{"name":"api_key","value":"CANARY_E5TREE09"}}"#)
                .unwrap();
        scrub_json_value(&mut siblings);
        let serialised = siblings.to_string();
        assert!(!serialised.contains("CANARY_E5TREE09"), "{serialised}");
    }

    // ---- B4-01/B4-02: the structured layer never rewrites non-secret JSON ----

    /// The guarantee under test, stated once: a JSON document (whole or a
    /// balanced substring) with nothing to redact comes back **byte for
    /// byte** — whitespace, escape spelling, duplicate keys, key order and
    /// every number lexeme included. When something *is* redacted, the
    /// changed region is re-serialised compactly with keys in input order
    /// (`preserve_order`) and numbers in their exact original lexemes
    /// (`arbitrary_precision`); non-secret content is then semantically, not
    /// byte, identical, and text outside the changed region is untouched.
    fn clean_json_payloads() -> Vec<String> {
        [
            r#"{"version":"0.1.0","pid":48213,"at":"2026-10-05 09:12:33"}"#,
            r#"{"agent":"main","tool":"shell","outcome":"allowed","reason":"command matched the allowlist"}"#,
            r#"{"agent":"main","tool":"read","outcome":"denied","reason":"path outside the workspace"}"#,
            r#"{"agent":"main","summary":"fetched https://example.com/docs","status":200,"duration_ms":183}"#,
            r#"{"run_id":18446744073709551615,"state":"ok"}"#,
            r#"{"weight":1e22,"ratio":0.1,"scale":1.0,"epsilon":1e-7}"#,
            r#"{"neg":-9223372036854775808,"big":123456789012345678901234567890}"#,
            r#"{"msg":"caf\u00e9 \u2014 fine","tags":["a","b"]}"#,
            r#"{"ordering":{"z":1,"a":2,"m":3}}"#,
            r#"{"dup":1,"dup":2}"#,
            r#"{
  "agent": "main",
  "jobs_total": 3,
  "jobs_enabled": 2,
  "running_job": null
}"#,
            r#"{"stop":false,"paused":false,"killed":false}"#,
            r#"{"usage_today":{"input_tokens":1234,"output_tokens":567,"requests":12}}"#,
            r#"{"input_tokens":18446744073709551615,"output_tokens":0}"#,
            r#"{"model":"deepseek-v4.1-flash","provider":"opencode-go"}"#,
            r#"{"sessions":[{"id":1,"agent":"main","messages":42},{"id":2,"agent":"side","messages":7}]}"#,
            r#"{"path":"/Users/someone/auxesis/crates/aux-tools/src/text.rs","bytes":12345}"#,
            r#"{"sha256":"3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3"}"#,
            r#"{"commit":"9f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90"}"#,
            r#"{"link":"https://example.com/docs?page=2","status":200}"#,
            r#"{"body":"line one\nline two","empty":""}"#,
            r#"{"escaped":"say \"hello\" and \\ the world","nested":"{\"detail\":{\"ok\":true}}"}"#,
            r#"{"tabs":"a\tb","slash":"a/b"}"#,
            r#"{"boolean":true,"nothing":null,"zero":0}"#,
            r#"{"arr":[],"obj":{}}"#,
            r#"{"deep":{"a":{"b":{"c":{"d":{"e":1}}}}}}"#,
            r#"{"list":[1,2,3,4,5,6,7,8,9,10]}"#,
            r#"{"mixed":[true,null,"s",3.5,{"k":"v"}]}"#,
            r#"{"ts":"2026-10-05T09:12:33Z","epoch":1759655553}"#,
            r#"{"email":"owner@example.com","name":"Alex"}"#,
            r#"{"message":"the quick brown fox jumps over the lazy dog"}"#,
            r#"{"assistant":"I will read the file and report back.\nNo changes made."}"#,
            r#"{"role":"assistant","content":"done — 3 tests green"}"#,
            r#"{"job":"nightly-backup","schedule":"0 3 * * *","enabled":true}"#,
            r#"{"next_run_at":"2026-10-06 03:00:00","last_run_at":"2026-10-05 03:00:02"}"#,
            r#"{"kind":"workspace.trust_requested","payload":{"agent":"main","fingerprint":"ab12cd34"}}"#,
            r#"{"fingerprint_sha256":"ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"}"#,
            r#"{"cache_hits":999999999999,"cache_misses":0}"#,
            r#"{"latency_p50_ms":12.75,"latency_p99_ms":1301.5}"#,
            r#"{"percent":100,"fraction":0.0001,"negative":-0.5}"#,
            r#"{"version":"v2.3.4-beta.1+build.5"}"#,
            r#"{"name":"agent-name","display":"Agent Name","hue":210}"#,
            r#"{"thread_id":null,"session_id":"7f2c1b3a-4d5e-6f70-8192-a3b4c5d6e7f8"}"#,
            r#"{
    "entries": [
        {"at": "2026-10-05 09:00:00", "kind": "daemon.started"},
        {"at": "2026-10-05 09:00:01", "kind": "message.user"}
    ],
    "limit": 50
}"#,
            r#"{"escaped_unicode":"\u0041\u0042\u0043","actual":"ABC"}"#,
            r#"{"solidus":"a\/b","tilde":"~"}"#,
            r#"{"array_of_arrays":[[1,2],[3,4],[[5]]]}"#,
            r#"{"unicode_text":"日本語のテキストと emoji 🚀","ascii":"ok"}"#,
            r#"{"summary":"nothing to see here","ok":true}"#,
            r#"{"nested_string":"{\"count\":10000000000000000000000}"}"#,
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    #[test]
    fn fifty_realistic_clean_payloads_survive_byte_for_byte() {
        let payloads = clean_json_payloads();
        assert_eq!(payloads.len(), 50, "the B4-01 corpus is the contract");
        let home = Path::new("/definitely-not-the-home");
        for (index, payload) in payloads.iter().enumerate() {
            assert_eq!(
                redact_secrets(payload),
                *payload,
                "redact_secrets altered payload {index}:\n{payload}"
            );
            assert_eq!(
                scrub_external_preview(home, payload, 1 << 20),
                *payload,
                "scrub_external_preview altered payload {index}:\n{payload}"
            );
        }
    }

    #[test]
    fn json_numbers_keep_their_exact_lexeme() {
        // B4-02: `arbitrary_precision` keeps the source spelling of every
        // number — no `f64` round trip, no exponent re-formatting.
        for lexeme in [
            "18446744073709551615", // u64::MAX
            "-9223372036854775808", // i64::MIN
            "123456789012345678901234567890",
            "1e22",
            "1E+22",
            "1e-7",
            "0.1",
            "1.0",
            "0.30000000000000004",
            "3.141592653589793238462643383279",
        ] {
            let raw = format!("{{\"n\":{lexeme},\"label\":\"keep\"}}");
            assert_eq!(redact_secrets(&raw), raw, "number {lexeme} rewritten");
        }
        // The same holds when a sibling *is* redacted: only the secret's
        // value changes; number lexemes and key order survive.
        let raw =
            r#"{"z":18446744073709551615,"api_key":"CANARYNUM01abcdef","a":1e+22,"f":1.0,"k":0.1}"#;
        let clean = redact_secrets(raw);
        assert!(!clean.contains("CANARYNUM01abcdef"), "{clean}");
        for lexeme in ["18446744073709551615", "1e+22", "1.0", "0.1"] {
            assert!(clean.contains(lexeme), "{lexeme} lost in {clean}");
        }
        let z = clean.find("\"z\"").unwrap();
        let a = clean.find("\"a\"").unwrap();
        assert!(z < a, "key order changed: {clean}");
    }

    #[test]
    fn json_escapes_duplicate_keys_and_order_survive_the_clean_path() {
        let clean = [
            r#"{"caf\u00e9":"cr\u00e8me","solidus":"a\/b"}"#,
            r#"{"dup":1,"dup":2,"last":3}"#,
            r#"{"z":1,"a":2,"m":3}"#,
            "{\n  \"pretty\": true,\n  \"indent\": [1, 2]\n}\n",
            r#"{"nested":"{\"n\":10000000000000000000000}"}"#,
        ];
        let home = Path::new("/definitely-not-the-home");
        for raw in clean {
            assert_eq!(redact_secrets(raw), raw, "rewritten: {raw}");
            assert_eq!(scrub_external_preview(home, raw, 1 << 20), raw);
        }
    }

    #[test]
    fn a_redacted_document_stays_semantically_identical() {
        // When something IS redacted, the changed region is re-serialised
        // compactly: whitespace normalises and escapes may normalise to
        // UTF-8, but keys keep input order, numbers keep their lexemes and
        // duplicate keys follow documented JSON semantics (last one wins).
        // Stated guarantee: byte-identical when clean, semantically identical
        // when redacted.
        let raw = "{\n  \"api_key\": \"CANARYSEM01abcdef\",\n  \"msg\": \"caf\\u00e9\",\n  \"dup\": 1,\n  \"dup\": 2,\n  \"n\": 1e+22\n}\n";
        let clean = redact_secrets(raw);
        assert!(!clean.contains("CANARYSEM01abcdef"), "{clean}");
        assert!(clean.contains("café"), "{clean}");
        assert!(clean.contains("1e+22"), "{clean}");
        assert_eq!(clean.matches("\"dup\"").count(), 1, "{clean}");
        assert!(clean.contains("\"dup\":2"), "{clean}");
        let api = clean.find("\"api_key\"").unwrap();
        let msg = clean.find("\"msg\"").unwrap();
        let n = clean.find("\"n\"").unwrap();
        assert!(api < msg && msg < n, "key order changed: {clean}");
        assert!(
            !clean.contains('\n'),
            "redacted document is compact: {clean}"
        );
    }

    #[test]
    fn padded_json_keys_are_classified_after_trim() {
        // B5-02: a single padding space inside the quotes switched both
        // layers off.
        let clean = redact_secrets(r#"{ " api_key " : "CANARY_B5PAD01" }"#);
        assert!(!clean.contains("CANARY_B5PAD01"), "{clean}");
        assert!(clean.contains("<redacted>"), "{clean}");
        let clean = redact_secrets(r#"{" api_key ":"CANARY_B5PAD02"}"#);
        assert!(!clean.contains("CANARY_B5PAD02"), "{clean}");
        // Not JSON: the quoted-name rule skips the same padding.
        let clean = redact_secrets(r#"" api_key " = CANARY_B5PAD03"#);
        assert!(!clean.contains("CANARY_B5PAD03"), "{clean}");
        assert!(clean.contains("<redacted>"), "{clean}");
        // An ordinary quoted phrase is untouched.
        assert_eq!(
            redact_secrets(r#"" a key point " and more"#),
            r#"" a key point " and more"#
        );
    }

    #[test]
    fn numeric_json_values_under_secret_names_are_redacted() {
        // B5-03: an 18-digit key under `api_key` used to survive the JSON
        // walk; epoch/counter-shaped numbers stay readable.
        assert_eq!(
            redact_secrets(r#"{"api_key":123456789012345678}"#),
            r#"{"api_key":"<redacted>"}"#
        );
        let clean = redact_secrets(r#"{"password":12345678901234567890}"#);
        assert!(!clean.contains("12345678901234567890"), "{clean}");
        assert_eq!(
            redact_secrets(r#"{"token":1699999999999}"#),
            r#"{"token":1699999999999}"#
        );
        assert_eq!(redact_secrets(r#"{"port":5432}"#), r#"{"port":5432}"#);
    }

    #[test]
    fn serde_json_arbitrary_precision_features_stay_workspace_unified() {
        // H-11: `arbitrary_precision` + `preserve_order` unify across the
        // whole workspace (kernel-broker/Cargo.toml): the structured scrub keeps
        // each number's original lexeme and each key's input order even when
        // a sibling is redacted. The historical sharp edge is a numeric
        // field under `#[serde(flatten)]`/untagged: with `arbitrary_precision`
        // an older serde_json could not deserialize it, and a future numeric
        // field would have failed silently at runtime. The three current
        // flatten/untagged call sites (the daemon snapshot/agents,
        // the app's providers crate openai_compat) carry no numeric fields; this pin
        // proves numbers are handled today and makes the failure mode loud if
        // that changes.
        #[derive(serde::Deserialize, Debug)]
        struct TypedFlatten {
            name: String,
            #[serde(flatten)]
            extra: std::collections::BTreeMap<String, u64>,
        }
        let typed: TypedFlatten = serde_json::from_str(r#"{"name":"x","count":3}"#)
            .expect("flattened numbers must deserialize under arbitrary_precision");
        assert_eq!(typed.name, "x");
        assert_eq!(typed.extra.get("count"), Some(&3));

        #[derive(serde::Deserialize, Debug)]
        #[serde(untagged)]
        enum Untagged {
            Pair { name: String, count: u64 },
        }
        let untagged: Untagged = serde_json::from_str(r#"{"name":"x","count":3}"#)
            .expect("untagged numbers must deserialize under arbitrary_precision");
        match untagged {
            Untagged::Pair { name, count } => {
                assert_eq!(name, "x");
                assert_eq!(count, 3);
            }
        }

        // And the structured layer keeps every lexeme of such a document.
        let raw = r#"{"name":"x","count":18446744073709551615,"ratio":1e+22}"#;
        assert_eq!(redact_secrets(raw), raw);
    }
}
