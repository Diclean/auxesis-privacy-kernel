//! The linearity check for the exact-value layer at one megabyte.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "timing test: run alone with --ignored --test-threads=1"]
    fn known_secret_layer_is_linear_at_one_megabyte() {
        // H-04/L-1: the exact-value layer runs first on every scrub; with a
        // realistic one-key registry it must stay linear at 1 MiB for the
        // raw value, its split form and the ordinary adversarial shapes.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = format!("sk-{}", "CANARYKSCOST7f3a9c2e1b5d");
        assert!(register_known_secret(&secret));
        const SIZE: usize = 1024 * 1024;
        let half = secret.len() / 2;
        let dump_unit = xxd_dump(&secret);
        let shapes = |size: usize| -> Vec<(&'static str, String)> {
            let known_dump = dump_unit.repeat(size / dump_unit.len().max(1));
            vec![
                (
                    "known-raw",
                    format!("prefix {secret} suffix ").repeat(size / 40),
                ),
                (
                    "known-split",
                    format!("prefix {}\n{} suffix ", &secret[..half], &secret[half..])
                        .repeat(size / 40),
                ),
                ("long-line", "a".repeat(size)),
                (
                    "json-escaped-quotes",
                    "{\"a\":\"b\\\"c\"},".repeat(size / 15),
                ),
                (
                    "bracket-values",
                    "api_key=(abcdef123456) ".repeat(size / 23),
                ),
                (
                    "sibling-pairs",
                    "{\"name\":\"api_key\",\"value\":\"abcdef123456\"},".repeat(size / 45),
                ),
                // --- round 6: the hex spellings stay linear at 1 MiB ---
                (
                    "hex-separated",
                    "73 62 36 6b 37 58 71 32 6d 4e 76 52 \n".repeat(size / 35),
                ),
                (
                    "escaped-hex",
                    "\\x73\\x62\\x36\\x6b\\x37\\x58\\x71\\x32".repeat(size / 32),
                ),
                (
                    "xxd-dump",
                    "00000000: 7362 366b 3758 7132 6d4e 7652 7434 4c70  sb6k7Xq2mNvRt4Lp\n"
                        .repeat(size / 57),
                ),
                ("xxd-dump-of-known", known_dump),
            ]
        };
        // Linear means 4x the input costs about 4x the time; quadratic costs
        // 16x. Compare each shape at n and 4n (best of 3 runs each) instead of
        // a wall-clock budget, which flakes on a loaded machine. The hang guard
        // is only for a true blow-up.
        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(30);
        let best_of_three = |label: &str, text: &str| -> std::time::Duration {
            (0..3)
                .map(|_| {
                    let started = std::time::Instant::now();
                    let _ = crate::text::redact_secrets(text);
                    let elapsed = started.elapsed();
                    assert!(
                        elapsed < HANG_GUARD,
                        "{label}: {elapsed:?} on {} bytes (hang guard {HANG_GUARD:?})",
                        text.len()
                    );
                    elapsed
                })
                .min()
                .unwrap_or_default()
        };
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
        clear_known_secrets();
    }
}
