//! Tests for log identity redaction: JIDs, grouped phone numbers and
//! digit runs.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_number_candidates_mask_leaks_and_preserve_allow_patterns() {
        for raw in [
            "phone=12 34 56 78",
            "06 12 34 56 78:12",
            "06 12 34 56 78:00",
            "06 12 34 56 78abc",
            "phone06 12 34 56 78",
            "06 12 34 56 78z",
            "06  12 34 56 78",
            "06,12,34,56,78",
            "06_12_34_56_78",
            "06+12+34+56+78",
            "06\\u0031 23 45 67 89",
            "０６ １２ ３４ ５６ ７８",
            "٠٦ ١٢ ٣٤ ٥٦ ٧٨",
            "06\u{0301}12 34 56 78",
            "06\u{058a}12\u{058a}34\u{058a}56\u{058a}78",
        ] {
            let clean = super::redact_grouped_phone_numbers(raw);
            assert!(!clean.chars().any(|c| c.is_numeric()), "{raw} -> {clean}");
            assert!(clean.contains("<number>"), "{raw} -> {clean}");
        }
        for keep in [
            "2026-10-08 22:28:46",
            "2026-10-08T22:28:46.123Z",
            "22:28",
            "127.0.0.1:2893",
            "host: 192.168.10.10",
            "192.168.1.100:443",
            "1.2.3",
            "12.5ms",
            "port 2893",
        ] {
            assert_eq!(super::redact_grouped_phone_numbers(keep), keep);
        }
    }

    #[test]
    fn log_identifiers_do_not_join_phone_groups_across_line_breaks() {
        for line_break in ['\n', '\r'] {
            let raw = format!("06 12 34{line_break}56 78");
            assert_eq!(super::redact_grouped_phone_numbers(&raw), raw);
        }
    }

    #[test]
    fn grouped_number_scan_is_linear_on_four_megabytes() {
        let input = "06,12,34,56,78 ".repeat(4 * 1024 * 1024 / 15);
        let output = super::redact_grouped_phone_numbers(&input);
        assert_eq!(output.matches("<number>").count(), 1);
    }

    #[test]
    fn log_identifiers_mask_jids_and_long_digit_runs() {
        // The P3 batch-2 log-hygiene canary (assembled at runtime so no phone
        // number literal is committed): a `whatsapp-rust` INFO line carrying a
        // number and a JID comes out redacted.
        let number = ["336", "0000", "0000"].concat();
        let jid = format!("{number}@s.whatsapp.net");
        let line = format!("Identity change for +{number} ({jid})");
        let masked = redact_log_line(&line);
        assert!(!masked.contains(&number), "number leaked: {masked}");
        assert!(masked.contains("<number>"), "no number mask: {masked}");
        assert!(masked.contains("<jid>"), "no JID mask: {masked}");
        assert!(
            masked.contains("s.whatsapp.net"),
            "the JID server (no identity) stays: {masked}"
        );

        // Ordinary prose, short numbers and non-JID servers are untouched.
        for keep in [
            "disk-usage is high",
            "port 1234 and pid 5678",
            "user@example.com",
            "12@s.whatsapp.netX",
            "1@s.whatsapp.net",
        ] {
            assert_eq!(redact_identifiers(keep), keep, "mangled {keep:?}");
        }
        assert_eq!(redact_identifiers("call 1234567"), "call 1234567");
        assert_eq!(
            redact_identifiers("call 12345678"),
            "call <number>",
            "eight digits is the mask threshold"
        );
    }

    #[test]
    fn multibyte_separators_around_dates_never_panic_and_are_masked() {
        for raw in [
            "2026-10-08 \u{2014} 12 messages",
            "2026-10-08 \u{2013} 12 messages",
            "2026-01-\u{2014}12345678",
        ] {
            let clean = redact_log_line(raw);
            assert!(clean.contains("<number>"), "{raw} -> {clean}");
            assert!(!clean.chars().any(char::is_numeric), "{raw} -> {clean}");
        }
        for raw in ["\u{20ac}1", "\u{b7}1"] {
            assert_eq!(redact_log_line(raw), raw);
        }
    }

    #[test]
    fn escaped_separators_are_decoded_for_scanning() {
        for raw in [
            "06\\u{a0}12\\u{a0}34\\u{a0}56\\u{a0}78",
            "06\\u00a012\\u00a034\\u00a056\\u00a078",
            "06 12 34\\u{200b}56 78",
            "06 12 34\\u200b56 78",
            "06 12 34 \\u{2014} 56 78",
            "06 12 34 \\u2014 56 78",
        ] {
            let clean = redact_grouped_phone_numbers(raw);
            assert!(clean.contains("<number>"), "{raw} -> {clean}");
            assert!(!clean.chars().any(char::is_numeric), "{raw} -> {clean}");
        }
    }

    #[test]
    fn a_sentence_full_stop_after_a_jid_server_still_ends_the_jid() {
        for raw in ["1234567@s.whatsapp.net.", "1234567@lid.", "1234567@g.us."] {
            let clean = redact_identifiers(raw);
            assert!(clean.starts_with("<jid>"), "{raw} -> {clean}");
            assert!(!clean.contains("1234567"), "{raw} -> {clean}");
        }
        // A longer host name is not a JID server, so it is left alone.
        assert_eq!(
            redact_jid_identifiers("1234567@lid.example"),
            "1234567@lid.example"
        );
    }

    #[test]
    fn combining_marks_next_to_a_digit_never_split_a_number() {
        for raw in [
            "0\u{301}6 12 34 56 78",
            "06 12 34 56 78\u{301}",
            "\u{301}06 12 34 56 78",
            "06 12 34 56\u{301}\u{301} 78",
        ] {
            let clean = redact_grouped_phone_numbers(raw);
            assert!(clean.contains("<number>"), "{raw} -> {clean}");
            assert!(!clean.chars().any(char::is_numeric), "{raw} -> {clean}");
        }
    }

    #[test]
    fn four_separators_join_a_number_and_five_do_not() {
        assert_eq!(
            redact_grouped_phone_numbers("06....12....34....56"),
            "<number>"
        );
        // Documented limit: a fifth separator ends the candidate.
        let spaced = "06.....12.....34.....56";
        assert_eq!(redact_grouped_phone_numbers(spaced), spaced);
    }

    #[test]
    fn date_and_ipv4_shapes_are_masked_when_a_field_is_out_of_range() {
        for raw in [
            "0612-10-08 12:34",
            "061.234.56.78",
            "10.0.0.256:8080",
            "1.20260101.0",
        ] {
            assert_eq!(redact_grouped_phone_numbers(raw), "<number>", "{raw}");
        }
        for keep in [
            "2026-10-08",
            "2026-10-08 22:28:46",
            "2026-10-08T22:28:46.123Z",
            "host: 192.168.10.10",
            "127.0.0.1:2893",
            "192.168.1.100:443",
        ] {
            assert_eq!(redact_grouped_phone_numbers(keep), keep);
        }
    }

    #[test]
    fn version_or_ip_shaped_phone_numbers_are_masked() {
        for raw in [
            "415.555.1234",
            "call 415.555.1234 now",
            "212.555.0100",
            "415.555.\u{ff11}\u{ff12}\u{ff13}\u{ff14}",
        ] {
            let clean = redact_identifiers(raw);
            assert!(clean.contains("<number>"), "{raw} -> {clean}");
            assert!(!clean.contains("555"), "{raw} -> {clean}");
            assert!(!clean.chars().any(char::is_numeric), "{raw} -> {clean}");
        }
    }

    #[test]
    fn mathematical_digits_count_as_digits() {
        // Bold, double-struck, sans, sans-bold and monospace digit sets.
        for zero in [0x1d7ce_u32, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6] {
            let raw: String = (0..8u32)
                .map(|offset| char::from_u32(zero + offset).expect("mathematical digit"))
                .collect();
            assert_eq!(redact_grouped_phone_numbers(&raw), "<number>", "{raw}");
        }
    }

    #[test]
    fn readable_shapes_survive_the_whole_log_path() {
        for keep in [
            "2026-10-08 22:28:46",
            "2026-10-08T22:28:46.123Z",
            "22:28",
            "127.0.0.1:2893",
            "host: 192.168.10.10",
            "192.168.1.100:443",
            "1.2.3",
            "v1.2.3",
            "rustc 1.90.0",
            "12.5ms",
            "port 2893",
        ] {
            assert_eq!(redact_identifiers(keep), keep, "mangled {keep:?}");
            assert_eq!(redact_log_line(keep), keep, "mangled {keep:?}");
        }
    }

    #[test]
    fn multibyte_text_at_every_scan_window_edge_never_panics() {
        // The header, quoted-key and `//` windows are byte counts: each one
        // must be rounded to a character boundary before it slices.
        for pad in 0..4 {
            let spaces = " ".repeat(pad);
            let cases = [
                format!("{spaces}Authorization: {}", "\u{20ac}".repeat(400)),
                format!("{spaces}{}\"api_key\"\u{ff1a}secret", "\u{e9}".repeat(200)),
                format!("{spaces}api_key = // x{}", "\u{e9}".repeat(200)),
            ];
            for raw in &cases {
                let _ = redact_log_line(raw);
            }
            if pad == 0 {
                assert!(!redact_log_line(&cases[0]).contains('\u{20ac}'));
            }
        }
    }

    #[test]
    fn redaction_never_panics_on_random_mixed_text() {
        // Tiny deterministic generator (Knuth's MMIX constants). A fixed seed
        // keeps the corpus reproducible without a new dependency.
        struct Lcg(u64);
        impl Lcg {
            fn below(&mut self, bound: usize) -> usize {
                let next = self.0.wrapping_mul(6_364_136_223_846_793_005);
                self.0 = next.wrapping_add(1_442_695_040_888_963_407);
                usize::try_from((self.0 >> 33) % bound as u64).unwrap_or(0)
            }
        }
        fn fuzz_piece(index: usize) -> &'static str {
            match index {
                0 => "-",
                1 => ":",
                2 => ".",
                3 => " ",
                4 => "/",
                5 => "+",
                6 => "T",
                7 => "Z",
                8 => "=",
                9 => "\"",
                10 => "(",
                11 => ")",
                12 => "@",
                13 => "\n",
                14 => "2026-10-08",
                15 => "22:28:46",
                16 => "api_key",
                17 => "Authorization: ",
                18 => "\\u00a0",
                19 => "\\u{2014}",
                20 => "\\u0031",
                21 => "\\u{301}",
                22 => "@s.whatsapp.net.",
                _ => "\u{ff1a}",
            }
        }
        fn fuzz_multibyte(index: usize) -> char {
            match index {
                0 => '\u{e9}',
                1 => '\u{2014}',
                2 => '\u{20ac}',
                3 => '\u{b7}',
                4 => '\u{4e2d}',
                5 => '\u{1f600}',
                6 => '\u{301}',
                7 => '\u{200b}',
                8 => '\u{ff11}',
                9 => '\u{1d7ce}',
                _ => '\u{a0}',
            }
        }
        let mut rng = Lcg(0x00c0_ffee_5eed_2026);
        for case in 0..20_000 {
            // Every fiftieth case is long enough to cross the byte windows.
            let pieces = if case % 50 == 0 { 300 } else { rng.below(24) };
            let mut input = String::new();
            for _ in 0..pieces {
                match rng.below(3) {
                    0 => input.push(char::from(b'0' + rng.below(10) as u8)),
                    1 => input.push_str(fuzz_piece(rng.below(24))),
                    _ => input.push(fuzz_multibyte(rng.below(11))),
                }
            }
            let _ = redact_grouped_phone_numbers(&input);
            let _ = redact_log_line(&input);
        }
    }

    #[test]
    fn a_panicking_log_redaction_yields_the_fixed_placeholder() {
        let line = "Authorization: Bearer secret-value-1234 06 12 34 56 78";
        crate::install_payload_free_panic_hook();
        let out = guard_log_redaction(line, |_| panic!("redaction bug"));
        assert_eq!(out, REDACTION_ERROR_LINE);
        assert!(!out.contains("secret-value"), "{out}");
        // The guard leaves the thread usable: the next line redacts normally.
        assert_eq!(
            redact_log_line_guarded("call 06 12 34 56 78"),
            "call <number>"
        );
    }

    #[test]
    fn bare_dotted_quads_are_masked_and_endpoints_stay_readable() {
        assert_eq!(redact_grouped_phone_numbers("41.23.45.67"), "<number>");
        assert_eq!(redact_grouped_phone_numbers("192.168.10.10"), "<number>");
        assert_eq!(
            redact_grouped_phone_numbers("call 12.34.56.78"),
            "call <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("ship 41.23.45.67"),
            "ship <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("the tip 41.23.45.67"),
            "the tip <number>"
        );
        // `from` and `to` introduce a sender or a recipient, not an endpoint.
        assert_eq!(
            redact_grouped_phone_numbers("call me from 12.34.56.78"),
            "call me from <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("from the server at 41.23.45.67"),
            "from the server at <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("to 41.23.45.67"),
            "to <number>"
        );
        // A context word counts only when it sits right before the address,
        // with at most two of `=`, `:`, space or `"` between them.
        assert_eq!(
            redact_grouped_phone_numbers("host:  41.23.45.67"),
            "host:  <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("host = 41.23.45.67"),
            "host = <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("host and 41.23.45.67"),
            "host and <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("hosts=41.23.45.67"),
            "hosts=<number>"
        );
        for keep in [
            "host: 192.168.1.10",
            "host: 192.168.10.10",
            "host=\"41.23.45.67\"",
            "192.168.1.100:443",
            "127.0.0.1",
            "127.255.255.255",
            "0.0.0.0",
            "peer=10.0.0.5",
            "peer=192.168.10.10",
            "peer=41.23.45.67",
            "IP: 41.23.45.67",
            "Client=41.23.45.67",
        ] {
            assert_eq!(redact_grouped_phone_numbers(keep), keep, "{keep}");
        }
    }

    #[test]
    fn clock_fractions_offsets_and_commas_stay_readable() {
        for keep in [
            "22:28:46.123456789",
            "2026-10-08T22:28:46.123456789Z",
            "2026-10-08 22:28:46 +0000",
            "2026-10-08 22:28:46,123",
            "22:28+0200",
            "22:28:46-05:00",
        ] {
            assert_eq!(redact_identifiers(keep), keep, "mangled {keep:?}");
            assert_eq!(redact_log_line(keep), keep, "mangled {keep:?}");
        }
        // A fraction past nanoseconds, or an out-of-range zone, is not a clock.
        assert_eq!(redact_identifiers("22:28:46.1234567890"), "<number>");
        assert_eq!(redact_identifiers("22:28+2560"), "<number>");
    }

    #[test]
    fn unicode_sixteen_digit_blocks_count_as_digits() {
        for zero in [0x10d40_u32, 0x11bf0, 0x16130, 0x16d70, 0x1ccf0, 0x1e5f1] {
            let raw: String = (0..8u32)
                .map(|offset| char::from_u32(zero + offset).expect("decimal digit"))
                .collect();
            assert_eq!(redact_grouped_phone_numbers(&raw), "<number>", "{raw}");
        }
    }
}
