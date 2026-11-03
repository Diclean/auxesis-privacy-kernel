//! Performance guards: every adversarial shape must stay linear.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "timing test: run alone with --ignored --test-threads=1"]
    fn redaction_is_linear_on_every_adversarial_shape() {
        // B2-04/P3-7 + round 3: 42 adversarial shapes at 256 KiB must each
        // stay linear. The old JWT scan was quadratic on repeated `eyJ`
        // (159 s at 256 KiB); the structured pass must not reintroduce it.
        const SIZE: usize = 256 * 1024;
        let shapes = |size: usize| -> Vec<(&'static str, String)> {
            vec![
                ("jwt-prefix", "eyJ".repeat(size / 3)),
                ("assignment-eq", "a=".repeat(size / 2)),
                ("token-ab", "token=ab ".repeat(size / 9)),
                ("vendor-sk", "sk-".repeat(size / 3)),
                ("vendor-nested", "sk-sk-".repeat(size / 6)),
                ("aux-key", "AUX_KEY_X=ab ".repeat(size / 12)),
                (
                    "authorization-none",
                    "authorization: none\n".repeat(size / 20),
                ),
                ("bearer-words", "Bearer bonds ".repeat(size / 13)),
                ("cert", "-----BEGIN CERTIFICATE-----\n".repeat(size / 28)),
                (
                    "pem-label",
                    "-----BEGIN private key-----\n".repeat(size / 29),
                ),
                (
                    "pem-open",
                    format!("-----BEGIN private key-----\n{}", "x".repeat(size)),
                ),
                ("putty", "PuTTY-User-Key-File-3:".repeat(size / 23)),
                ("base64", "aGVsbG8=\n".repeat(size / 9)),
                ("nested-quotes", "\"a\\\"b\\\"c\" ".repeat(size / 10)),
                ("long-line", "a".repeat(size)),
                ("quotes-only", "\"".repeat(size)),
                ("backslashes", "\\".repeat(size)),
                ("equals-only", "=".repeat(size)),
                ("colons-only", ":".repeat(size)),
                ("dashes", "-".repeat(size)),
                ("schemes", "://".repeat(size / 3)),
                ("unicode-zwsp", "a\u{200b}=b ".repeat(size / 7)),
                ("url-userinfo", "postgres://u:pass@h/d ".repeat(size / 21)),
                ("url-noat-long", format!("postgres://{}", "a".repeat(size))),
                ("json-array", "[\"abcdef\",".repeat(size / 10)),
                (
                    "json-nested",
                    format!("{}1{}", "[".repeat(2000), "]".repeat(2000)),
                ),
                (
                    "json-deep-obj",
                    format!("{}\"a\":1{}", "{\"a\":".repeat(800) + "{", "}".repeat(801)),
                ),
                (
                    "json-pretty-multiline",
                    "{\n  \"api_key\":\n    \"abcdef123456\"\n}\n".repeat(size / 36),
                ),
                (
                    "json-escaped-quotes",
                    "{\"a\":\"b\\\"c\"},".repeat(size / 15),
                ),
                ("percent-sep", "api_key%3Dabcdef123456 ".repeat(size / 22)),
                ("quoted-token", "\"token\":\"abcdef\",".repeat(size / 19)),
                ("colon-pair", "api_key: abcdef123456 ".repeat(size / 21)),
                ("cookie-header", "Cookie: a=1; b=2\n".repeat(size / 17)),
                (
                    "cookie-header-blank",
                    format!("Cookie:{}", " ".repeat(size)),
                ),
                ("semicolons", ";".repeat(size)),
                ("commas", ",".repeat(size)),
                ("long-line-spaces", " ".repeat(size)),
                (
                    "percent-url",
                    "postgres%3A%2F%2Fu:pass@h/d ".repeat(size / 25),
                ),
                ("fullwidth-sep", "api_key＝abcdef ".repeat(size / 18)),
                (
                    "json-in-json",
                    "{\"detail\":\"{\\\"api_key\\\":\\\"abcdef123456\\\"}\"},".repeat(size / 43),
                ),
                (
                    "cookie-jar",
                    "session=abcdef123456; Path=/; HttpOnly\n".repeat(size / 37),
                ),
                (
                    "mixed-randomish",
                    [
                        "token=ab ",
                        "api_key%3Dabcdef ",
                        "\"token\":\"abcdef\",",
                        "postgres://u:pass@h/d ",
                        "Cookie: a=1; b=2\n",
                        "{\"a\":\"b\\\"c\"},",
                        "session=abcdef123456; ",
                        "Bearer bonds ",
                        "-----BEGIN CERTIFICATE-----\n",
                        "a\u{200b}=b ",
                    ]
                    .iter()
                    .cycle()
                    .take(size / 20)
                    .copied()
                    .collect::<String>(),
                ),
                // --- round 5: the new shapes are all bounded, one pass each ---
                (
                    "bracket-values",
                    "api_key=(abcdef123456) ".repeat(size / 23),
                ),
                (
                    "padded-json-key",
                    "{\" api_key \":\"abcdef123456\"},".repeat(size / 29),
                ),
                (
                    "folded-bearer",
                    "Bearer\n abcdefghijklmnopqrst ".repeat(size / 29),
                ),
                (
                    "sibling-pairs",
                    "{\"name\":\"api_key\",\"value\":\"abcdef123456\"},".repeat(size / 45),
                ),
                (
                    "fullwidth-prose",
                    "全角記号：ＡＢＣ－ＸＹＺ，！？ 简体中文、，。".repeat(size / 65),
                ),
            ]
        };
        assert_eq!(
            shapes(SIZE).len(),
            47,
            "the 47-shape cost table is the contract"
        );
        // Linear means 4x the input costs about 4x the time; quadratic costs
        // 16x. Compare each shape at n and 4n, not against a wall-clock budget
        // that flakes when the machine is loaded. The hang guard is only for
        // a true blow-up.
        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(30);
        fn best_of_three(label: &str, text: &str) -> std::time::Duration {
            (0..3)
                .map(|_| {
                    let started = std::time::Instant::now();
                    let _ = redact_secrets(text);
                    let elapsed = started.elapsed();
                    assert!(
                        elapsed < HANG_GUARD,
                        "{label}: redaction took {elapsed:?} on {} bytes (hang guard {HANG_GUARD:?})",
                        text.len()
                    );
                    elapsed
                })
                .min()
                .unwrap_or_default()
        }
        let floor = std::time::Duration::from_millis(1);
        for ((label, small), (_, large)) in shapes(SIZE / 4).into_iter().zip(shapes(SIZE)) {
            let t_small = best_of_three(label, &small);
            let t_large = best_of_three(label, &large);
            assert!(
                t_large <= t_small.max(floor) * 12,
                "{label}: {t_large:?} on {} bytes vs {t_small:?} on {} bytes (4x input must cost under 12x time)",
                large.len(),
                small.len()
            );
        }
        // The shape that used to be quadratic, at its own size.
        let mut pem = String::from("-----BEGIN private key-----\n");
        pem.push_str(&"x".repeat(SIZE));
        let started = std::time::Instant::now();
        assert!(!redact_secrets(&pem).contains(&"x".repeat(64)));
        assert!(
            started.elapsed() < HANG_GUARD,
            "private PEM block took {:?} (hang guard {HANG_GUARD:?})",
            started.elapsed()
        );
    }
}
