//! Escaped-spelling regressions: `\u`/`\x`/percent runs, nested and mixed
//! layers, and the fail-closed path when a run cannot be resolved.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn nested_first_byte(secret: &str, layers: usize) -> String {
        let mut head = format!("\\x{:02x}", secret.as_bytes()[0]);
        for _ in 1..layers {
            head = head.replace('\\', "\\u005c");
        }
        format!("{head}{}", &secret[1..])
    }

    #[test]
    fn scrub_u_esc_nested_escape_layers_of_a_known_value_are_masked() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("NESTED");
        assert!(register_known_secret(&secret));
        for layers in [1, 2, 3, 10] {
            let spelling = nested_first_byte(&secret, layers);
            let text = format!("before {spelling} after");
            assert!(redact_known_secrets(&text).as_deref() == Some("before <redacted> after"));
        }
        clear_known_secrets();
    }

    #[test]
    fn scrub_u_esc_mixed_escape_families_decode_together() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("MIXED");
        assert!(register_known_secret(&secret));
        let spelling = format!(
            "\\u{:04x}\\x{:02x}%{:02x}{}",
            secret.as_bytes()[0],
            secret.as_bytes()[1],
            secret.as_bytes()[2],
            &secret[3..]
        );
        let text = format!("before {spelling} after");
        assert!(redact_known_secrets(&text).as_deref() == Some("before <redacted> after"));
        for head in ["%5Cu0043", "\\\\u0043", "\\u005cx43"] {
            let text = format!("before {head}{} after", &secret[1..]);
            assert!(redact_known_secrets(&text).as_deref() == Some("before <redacted> after"));
        }
        let tail = unique("OCTAL");
        assert!(register_known_secret(&format!("Ā{tail}")));
        assert!(redact_known_secrets(&format!("\\400{tail}")).is_none());
        clear_known_secrets();
    }
    macro_rules! escape_regression {
        ($name:ident, $plain:literal, $escaped:literal) => {
            #[test]
            fn $name() {
                let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
                clear_known_secrets();
                let tail = unique("ESC");
                assert!(register_known_secret(&format!("{}{tail}", $plain)));
                let clean = redact_known_secrets(&format!("{}{tail}", $escaped));
                assert_eq!(clean.as_deref(), Some("<redacted>"));
                clear_known_secrets();
            }
        };
    }
    escape_regression!(scrub_u_esc_json_slash, "sensitive/", r"sensitive\/");
    escape_regression!(scrub_u_esc_octal, "sensitive-", r"\163ensitive-");
    escape_regression!(scrub_u_esc_percent_u, "sensitive-", "%u0073ensitive-");
    escape_regression!(scrub_u_esc_octal_max, "ÿ7", r"\3777");
    escape_regression!(scrub_u_esc_percent_u_surrogates, "😀", "%uD83D%uDE00");

    #[test]
    fn scrub_u_esc_escape_run_split_across_stream_chunks_is_withheld() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("STREAM");
        assert!(register_known_secret(&secret));
        let encode = |s: &str| s.bytes().map(|b| format!("\\u{b:04x}")).collect::<String>();
        let spelling = encode(&encode(&encode(&secret)));
        let prefix = "public ".repeat(100);
        let split = spelling.len() / 2 + 1;
        let partial = format!("{prefix}{}", &spelling[..split]);
        let cut = stream_prefix_cut(&partial);
        assert!(cut <= prefix.len(), "a partial escape run was published");
        let whole = format!("{prefix}{spelling} end");
        assert!(crate::text::redact_secrets(&whole)
            .starts_with(&crate::text::redact_secrets(&partial[..cut])));
        clear_known_secrets();
    }

    #[test]
    fn scrub_u_esc_unresolved_escape_run_fails_closed_at_the_pass_cap() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("CAP");
        assert!(register_known_secret(&secret));
        let spelling = nested_first_byte(&secret, 20);
        let text = format!("before {spelling} after");
        assert!(redact_known_secrets(&text).as_deref() == Some("before <redacted> after"));
        let oversized = format!("before {}{spelling} after", "z".repeat(4 * 1024 * 1024));
        assert!(redact_known_secrets(&oversized).as_deref() == Some("before <redacted> after"));
        let settled = format!(
            "{}{}",
            "\\u007a".repeat(100),
            nested_first_byte("unrelated", 16)
        );
        assert!(redact_known_secrets(&settled).is_none());
        clear_known_secrets();
    }

    #[test]
    fn scrub_u_esc_large_input_with_escaped_known_value_finishes_and_masks() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("LARGE");
        assert!(register_known_secret(&secret));
        let spelling = nested_first_byte(&secret, 3);
        let text = format!("{}{spelling} end", "z".repeat(200_000));
        let start = std::time::Instant::now();
        let clean = redact_known_secrets(&text).expect("escaped value must be masked");
        assert!(start.elapsed() < std::time::Duration::from_secs(30));
        assert!(clean.ends_with("<redacted> end"));
        clear_known_secrets();
    }
}
