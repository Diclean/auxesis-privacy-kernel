//! Every spelling family of a registered value: composed transforms, hex
//! dumps, case folds, unicode escapes, NFKC and the closure budgets.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use unicode_normalization::UnicodeNormalization;

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transformed_copies_of_a_known_value_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("TRANSFORM");
        assert!(register_known_secret(&secret));

        let base64 = STANDARD.encode(secret.as_bytes());
        let encoded = percent_encode(&secret, true);
        let json = serde_json::to_string(&secret).unwrap();
        let split = format!(
            "{}\n  {}",
            &secret[..secret.len() / 2],
            &secret[secret.len() / 2..]
        );
        let zero_width = format!("{}\u{200b}{}", &secret[..4], &secret[4..]);
        let cases = [secret.clone(), base64, encoded, json, split, zero_width];
        for case in cases {
            let raw = format!("value {case} end");
            let clean = redact_known_secrets(&raw)
                .unwrap_or_else(|| panic!("no match for transformed case {case:?}"));
            assert!(!clean.contains(&secret), "leaked via {case:?}: {clean}");
        }
        clear_known_secrets();
    }

    #[test]
    fn hex_encoded_known_values_are_redacted_in_every_dump_spelling() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("HEX");
        assert!(register_known_secret(&secret));

        let lower = test_hex(&secret, false);
        let upper = test_hex(&secret, true);
        let escaped: String = secret
            .bytes()
            .map(|byte| format!("\\x{byte:02x}"))
            .collect();
        let escaped_spaced: String = secret
            .bytes()
            .map(|byte| format!("\\x{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let zero_x_spaced: String = secret
            .bytes()
            .map(|byte| format!("0x{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let pairs: Vec<String> = secret.bytes().map(|byte| format!("{byte:02x}")).collect();
        let spaced = pairs.join(" ");
        let colon = pairs.join(":");
        let newline = pairs.join("\n");
        let xxd = xxd_dump(&secret);
        let hexdump = hexdump_dump(&secret);
        let od = od_dump(&secret);
        // SB6-01: the exact-value layer must see every one of these as the
        // same secret, with or without a credential name in front of it.
        let cases: Vec<(&str, String)> = vec![
            ("hex-lower", lower.clone()),
            ("hex-upper", upper.clone()),
            ("escaped", escaped.clone()),
            ("escaped-spaced", escaped_spaced.clone()),
            ("spaced", spaced.clone()),
            ("zero-x-spaced", zero_x_spaced.clone()),
            ("colon", colon.clone()),
            ("newline", newline.clone()),
            ("xxd", xxd.clone()),
            ("hexdump", hexdump.clone()),
            ("od", od.clone()),
        ];
        for (label, spelling) in cases {
            let text = format!("free text\n{spelling}\ninside");
            let clean = redact_known_secrets(&text)
                .unwrap_or_else(|| panic!("no match for {label} spelling"));
            assert!(clean.contains(MASK), "{label}: no marker in {clean:?}");
            assert!(
                !clean.contains(&spelling),
                "{label}: spelling survived as {clean:?}"
            );
        }
        // The dumps are line-shaped: the whole hex/ASCII block must be gone,
        // not just a single line of it.
        for (label, dump, first_pairs) in [
            ("xxd", &xxd, "7362 366b 3758 7132"),
            ("hexdump", &hexdump, "73 62 36 6b"),
            ("od", &od, "73  62  36  6b"),
        ] {
            let clean = redact_known_secrets(dump).unwrap_or_else(|| panic!("no {label} match"));
            assert!(
                !clean.contains(first_pairs),
                "{label}: first pairs survived: {clean:?}"
            );
        }
        // The plain spellings that happen to be hex are untouched when no
        // secret is registered.
        clear_known_secrets();
        assert!(redact_known_secrets(&format!("free text {spaced} inside")).is_none());
    }

    #[test]
    fn case_folded_copies_of_a_known_value_are_redacted() {
        // SB6-03: Aho-Corasick is byte-exact, so a log shipper or DB that
        // lower/upper-cases text must not defeat the exact layer. The canary
        // is mixed-case on purpose.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("CaseFold");
        assert!(register_known_secret(&secret));
        assert_ne!(secret.to_lowercase(), secret);
        assert_ne!(secret.to_uppercase(), secret);
        for (label, folded) in [
            ("lower", secret.to_lowercase()),
            ("upper", secret.to_uppercase()),
        ] {
            let text = format!("free text {folded} inside");
            let clean = redact_known_secrets(&text)
                .unwrap_or_else(|| panic!("no match for case-folded {label}"));
            assert!(clean.contains(MASK), "case-folded {label}: {clean:?}");
        }
        clear_known_secrets();
    }

    #[test]
    fn base32_and_base64url_copies_of_a_known_value_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("BASEFOLD");
        assert!(register_known_secret(&secret));
        let base32_pad = test_base32(&secret, true, false);
        let base32_plain = test_base32(&secret, false, false);
        let base32_lower = test_base32(&secret, true, true);
        let b64url = URL_SAFE_NO_PAD.encode(secret.as_bytes());
        for (label, case) in [
            ("base32-pad", base32_pad),
            ("base32-nopad", base32_plain),
            ("base32-lower", base32_lower),
            ("base64url-nopad", b64url),
        ] {
            let text = format!("free text {case} inside");
            let clean =
                redact_known_secrets(&text).unwrap_or_else(|| panic!("no match for {label}"));
            assert!(clean.contains(MASK), "{label}: {clean:?}");
            assert!(!clean.contains(&case), "{label}: {clean:?}");
        }
        clear_known_secrets();
    }

    #[test]
    fn percent_encoded_known_value_without_a_name_is_redacted() {
        // M12 pin: the percent-encoded needle is load-bearing. The heuristic
        // layers do not see this string as a credential (there is no name in
        // front of it and no `%3A%2F%2F` DSN shape), so dropping the
        // `percent_encode` needles from `secret_variants` makes this test
        // fail.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = format!("{}{}", "CANARY_KS_PCT_", "7f3a9c+2e/1b5d!");
        assert!(register_known_secret(&secret));
        let upper = percent_encode(&secret, true);
        let lower = percent_encode(&secret, false);
        assert_ne!(upper, secret, "the canary must actually percent-encode");
        for (label, spelling) in [("upper", &upper), ("lower", &lower)] {
            let text = format!("free text {spelling} inside");
            let clean = redact_known_secrets(&text)
                .unwrap_or_else(|| panic!("no match for percent-{label}"));
            assert!(clean.contains(MASK), "percent-{label}: {clean:?}");
        }
        clear_known_secrets();
    }

    /// dh-1 note: bidi isolate controls count as scrub noise, so a registered
    /// value stuffed with them is still masked whole — an isolate cannot hide
    /// a secret from the exact layer.
    #[test]
    fn bidi_isolates_do_not_hide_a_registered_value() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = format!("CNR7BIDI{}", 1_357_924_680u64);
        assert!(register_known_secret(&secret));
        let hidden: String = secret.chars().map(|c| format!("\u{2066}{c}")).collect();
        let text = format!("token={hidden} end");
        let clean = redact_known_secrets(&text).expect("the isolate-stuffed value must match");
        assert!(clean.contains(MASK), "{clean}");
        assert!(!clean.contains(&secret), "{clean}");
        clear_known_secrets();
    }

    #[test]
    fn unicode_escaped_copies_of_a_known_value_are_redacted() {
        // R7-4: a plain-ASCII value spelled as JSON/JS unicode escapes is the
        // same value; `\uNNNN`, `\UNNNNNNNN` and the braced `\u{NN}` /
        // `\u{NNNN}` forms (both hex cases, contiguous and separated) must
        // all be masked by the whole-buffer pass.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("UNIESC");
        assert!(register_known_secret(&secret));
        let bytes: Vec<u8> = secret.bytes().collect();
        let cases: Vec<(&str, String)> = vec![
            ("u4", bytes.iter().map(|b| format!("\\u{b:04x}")).collect()),
            (
                "u4-upper",
                bytes.iter().map(|b| format!("\\u{b:04X}")).collect(),
            ),
            ("U8", bytes.iter().map(|b| format!("\\U{b:08x}")).collect()),
            (
                "braced2",
                bytes.iter().map(|b| format!("\\u{{{b:02x}}}")).collect(),
            ),
            (
                "braced4",
                bytes.iter().map(|b| format!("\\u{{{b:04x}}}")).collect(),
            ),
            (
                "u4-separated",
                bytes
                    .iter()
                    .map(|b| format!("\\u{b:04x}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            (
                "braced-separated",
                bytes
                    .iter()
                    .map(|b| format!("\\u{{{b:02x}}}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            ),
        ];
        for (label, spelling) in cases {
            let text = format!("free text {spelling} inside");
            let clean =
                redact_known_secrets(&text).unwrap_or_else(|| panic!("no match for {label}"));
            assert!(clean.contains(MASK), "{label}: {clean:?}");
            assert!(!clean.contains(&spelling), "{label}: {clean:?}");
        }
        clear_known_secrets();
    }

    /// R8 (1): real NFKC — ligatures, fullwidth, superscripts and decomposed
    /// combining sequences — on both the text and the registered values,
    /// with exact offset mapping back to the original span.
    #[test]
    fn nfkc_compatibility_copies_of_a_known_value_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let fullwidth = |value: &str| -> String {
            value
                .chars()
                .map(|c| {
                    let cp = c as u32;
                    if (0x21..=0x7E).contains(&cp) {
                        char::from_u32(cp + 0xFEE0).unwrap_or(c)
                    } else {
                        c
                    }
                })
                .collect()
        };
        let pairs: Vec<(&str, String)> = vec![
            // Ligatures (U+FB01 fi, U+FB02 fl, U+FB03 ffi).
            ("officeCNR8alpha987", "of\u{FB01}ceCNR8alpha987".to_string()),
            ("flavorCNR8beta987", "\u{FB02}avorCNR8beta987".to_string()),
            ("officeCNR8gamma987", "o\u{FB03}ceCNR8gamma987".to_string()),
            // Fullwidth letters and digits (U+FF01..U+FF5E).
            ("officeCNR8delta987", fullwidth("officeCNR8delta987")),
            // Superscript digits (U+00B2, U+2079…).
            ("office2CNR8eps987", "office\u{B2}CNR8eps987".to_string()),
            (
                "office9CNR8zeta987",
                "office\u{2079}CNR8zeta987".to_string(),
            ),
            // Decomposed combining sequence vs the composed registered form.
            ("caf\u{E9}CNR8eta987", "cafe\u{301}CNR8eta987".to_string()),
        ];
        for (registered, spelled) in pairs {
            assert!(register_known_secret(registered));
            // The folded scan must reproduce real NFKC for the spelling.
            let (folded, _, _) = fold_nfkc(&spelled);
            assert_eq!(
                folded,
                spelled.nfkc().collect::<String>(),
                "fold_nfkc diverged from NFKC for {spelled:?}"
            );
            let text = format!("free text {spelled} inside");
            let clean = redact_known_secrets(&text)
                .unwrap_or_else(|| panic!("no match for {spelled:?} (registered {registered:?})"));
            assert!(clean.contains(MASK), "{spelled:?}: {clean:?}");
            assert!(!clean.contains(&spelled), "{spelled:?}: {clean:?}");
        }
        // The reverse direction: a registered compatibility spelling matches
        // the plain text through the value's own NFKC needle.
        for (registered, plain) in [
            ("of\u{FB01}ceCNR8theta987", "officeCNR8theta987"),
            ("cafe\u{301}CNR8iota987", "caf\u{E9}CNR8iota987"),
            ("office\u{B2}CNR8kappa987", "office2CNR8kappa987"),
        ] {
            assert!(register_known_secret(registered));
            let text = format!("free text {plain} inside");
            let clean = redact_known_secrets(&text)
                .unwrap_or_else(|| panic!("no match for {plain:?} (registered {registered:?})"));
            assert!(clean.contains(MASK), "{plain:?}: {clean:?}");
            assert!(!clean.contains(plain), "{plain:?}: {clean:?}");
        }
        clear_known_secrets();
    }

    /// R9 (1): full canonical NFKC — canonical mark reordering and Hangul
    /// Jamo composition — on both the text and the registered value.
    #[test]
    fn nfkc_canonical_reordering_and_hangul_copies_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let pairs = [
            // Conjoining Hangul Jamo vs precomposed syllables.
            (
                "\u{D55C}\u{AE00}CNR9KoreanSecret987",
                "\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}CNR9KoreanSecret987",
            ),
            // Canonically reordered combining marks: Å + U+0315.
            (
                "\u{C5}\u{0315}CNR9ZalgoSecret987",
                "A\u{0315}\u{030A}CNR9ZalgoSecret987",
            ),
            // Vietnamese stacked marks, both orders.
            (
                "Vi\u{1EC7}tCNR9VietA987",
                "Vie\u{0302}\u{0323}tCNR9VietA987",
            ),
            (
                "Vi\u{1EC7}tCNR9VietB987",
                "Vie\u{0323}\u{0302}tCNR9VietB987",
            ),
        ];
        for (registered, spelled) in pairs {
            assert!(register_known_secret(registered));
            assert_eq!(
                spelled.nfkc().collect::<String>(),
                registered,
                "the probe spelling must normalise to the registered value"
            );
            let (folded, _, _) = fold_nfkc(spelled);
            assert_eq!(folded, registered, "fold_nfkc diverged for {spelled:?}");
            let text = format!("public {spelled} suffix");
            let clean =
                redact_known_secrets(&text).unwrap_or_else(|| panic!("no match for {spelled:?}"));
            assert!(clean.contains(MASK), "{spelled:?}: {clean:?}");
            assert!(!clean.contains(spelled), "{spelled:?}: {clean:?}");
        }
        clear_known_secrets();
    }

    /// R10 (1): a value longer than the old 512-byte variant cap is
    /// registered and matched (raw and base64); anything over the
    /// registration cap is refused and never claimed as scrubbed.
    #[test]
    fn long_registered_values_are_matched_or_refused() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        // 513 bytes: the raw form used to be dropped by the 512-byte cap.
        let value_513 = "L".repeat(513);
        assert!(register_known_secret(&value_513));
        let text = format!("public {value_513} suffix");
        let clean = redact_known_secrets(&text).expect("the 513-byte value must match");
        assert!(clean.contains(MASK), "no mask in {} bytes", clean.len());
        assert!(!clean.contains(&value_513));
        // Its base64 spelling (684 bytes) is covered too.
        let b64 = STANDARD.encode(value_513.as_bytes());
        assert!(
            b64.len() > 512,
            "the base64 spelling must exceed the old cap"
        );
        let clean =
            redact_known_secrets(&format!("public {b64} suffix")).expect("base64 must match");
        assert!(clean.contains(MASK));
        clear_known_secrets();

        // Over the registration cap: refused, and never claimed as scrubbed.
        let too_long = "L".repeat(MAX_KNOWN_SECRET_LEN + 1);
        assert!(!register_known_secret(&too_long));
        assert!(redact_known_secrets(&format!("public {too_long} suffix")).is_none());
        clear_known_secrets();

        // 256 bytes: the full closure fits the byte budget and covers
        // base64-of-lower-hex (684 bytes) and base64-of-colon-hex.
        let value_256 = "L".repeat(256);
        assert!(register_known_secret(&value_256));
        assert!(
            !registry_oversized(),
            "a 256-byte secret must fit the variant budget"
        );
        let hex = hex_encode(&value_256, false);
        let b64_of_hex = STANDARD.encode(hex.as_bytes());
        assert!(b64_of_hex.len() > 512, "the repro spelling is 684 bytes");
        let clean =
            redact_known_secrets(&format!("public {b64_of_hex} suffix")).unwrap_or_else(|| {
                panic!(
                    "base64-of-lower-hex must match ({} bytes)",
                    b64_of_hex.len()
                )
            });
        assert!(clean.contains(MASK));
        let colon = hex_separated(&value_256, ":", false);
        let b64_of_colon = STANDARD.encode(colon.as_bytes());
        let clean = redact_known_secrets(&format!("public {b64_of_colon} suffix"))
            .unwrap_or_else(|| panic!("base64-of-colon-hex must match"));
        assert!(clean.contains(MASK));
        clear_known_secrets();
        assert!(!registry_oversized());
    }

    /// R10 (2): a value whose closure exceeds the budget is still registered
    /// (its raw form matches) but flags the registry oversized, so live
    /// streams fail closed instead of silently missing spellings.
    #[test]
    fn oversized_closures_register_and_flag_fail_closed() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let value = "K".repeat(1024);
        assert!(register_known_secret(&value));
        assert!(
            registry_oversized(),
            "a 1024-byte value's closure exceeds the budget"
        );
        let clean =
            redact_known_secrets(&format!("public {value} suffix")).expect("the raw must match");
        assert!(clean.contains(MASK));
        clear_known_secrets();
        assert!(!registry_oversized());

        // The documented threshold (GLM-P3): 409 bytes stays covered, 410
        // bytes cannot (the `0x`-of-hex composition passes the 4096-byte
        // needle cap there), so the registry fails every stream closed.
        assert!(register_known_secret(&"K".repeat(409)));
        assert!(
            !registry_oversized(),
            "409 bytes must stay under the closure threshold"
        );
        clear_known_secrets();
        assert!(register_known_secret(&"K".repeat(410)));
        assert!(
            registry_oversized(),
            "410 bytes is the documented closure threshold"
        );
        clear_known_secrets();
        assert!(!registry_oversized());
    }

    /// R9 (2): the depth-2 composition closure — every pair of transforms
    /// applied to a registered value is masked.
    #[test]
    fn composed_transform_pairs_of_a_known_value_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = "CNR9~Secret~987";
        assert!(register_known_secret(secret));
        let mut checked = 0usize;
        for &first in TRANSFORMS.iter() {
            let Some(step1) = apply_transform(first, secret) else {
                continue;
            };
            for &second in TRANSFORMS.iter() {
                let Some(step2) = apply_transform(second, &step1) else {
                    continue;
                };
                // The registration budget drops spellings longer than
                // `MAX_VARIANT_LEN` (the decoded scan still covers hex-family
                // spellings); the pair sweep follows the same budget.
                if step2.len() > MAX_VARIANT_LEN {
                    continue;
                }
                checked += 1;
                let text = format!("public {step2} suffix");
                let clean = redact_known_secrets(&text)
                    .unwrap_or_else(|| panic!("no match for the composed spelling {step2:?}"));
                assert!(clean.contains(MASK), "{step2:?}: {clean:?}");
                assert!(!clean.contains(&step2), "{step2:?}: {clean:?}");
            }
        }
        assert!(
            checked > 100,
            "the pair sweep must cover many pairs: {checked}"
        );
        clear_known_secrets();
    }

    /// R8 (2): JSON surrogate-pair escapes of a non-BMP character in a
    /// registered value, in every spelling the JSON/JS world uses.
    #[test]
    fn surrogate_pair_escaped_copies_of_a_known_value_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = format!("CNR8{}Surrogate987", '\u{1F600}');
        assert!(register_known_secret(&secret));
        let all_escaped: String = secret
            .chars()
            .map(|c| {
                let code = c as u32;
                if code > 0xFFFF {
                    format!(
                        "\\u{:04X}\\u{:04X}",
                        surrogate_pair(code).0,
                        surrogate_pair(code).1
                    )
                } else {
                    format!("\\u{code:04X}")
                }
            })
            .collect();
        let all_escaped_lower: String = secret
            .chars()
            .map(|c| {
                let code = c as u32;
                if code > 0xFFFF {
                    format!(
                        "\\u{:04x}\\u{:04x}",
                        surrogate_pair(code).0,
                        surrogate_pair(code).1
                    )
                } else {
                    format!("\\u{code:04x}")
                }
            })
            .collect();
        let cases = [
            ("mixed-upper", "CNR8\\uD83D\\uDE00Surrogate987".to_string()),
            ("mixed-lower", "CNR8\\ud83d\\ude00Surrogate987".to_string()),
            ("U8", "CNR8\\U0001F600Surrogate987".to_string()),
            ("braced", "CNR8\\u{1F600}Surrogate987".to_string()),
            ("all-escaped-upper", all_escaped),
            ("all-escaped-lower", all_escaped_lower),
        ];
        for (label, spelling) in cases {
            let text = format!("free text {spelling} inside");
            let clean =
                redact_known_secrets(&text).unwrap_or_else(|| panic!("no match for {label}"));
            assert!(clean.contains(MASK), "{label}: {clean:?}");
            assert!(!clean.contains(&spelling), "{label}: {clean:?}");
        }
        clear_known_secrets();
    }

    #[test]
    fn fullwidth_copies_of_a_known_value_are_redacted() {
        // R7 P3: NFKC-compatible fullwidth letters/digits are the same value
        // to a human and to any NFKC normaliser; the whole-buffer pass folds
        // them and masks the original span.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("NFKC");
        assert!(register_known_secret(&secret));
        let fullwidth: String = secret
            .chars()
            .map(|c| {
                let cp = c as u32;
                if (0x21..=0x7E).contains(&cp) {
                    char::from_u32(cp + 0xFEE0).unwrap_or(c)
                } else {
                    c
                }
            })
            .collect();
        let text = format!("free text {fullwidth} inside");
        let clean = redact_known_secrets(&text).expect("the fullwidth value must match");
        assert!(clean.contains(MASK), "{clean:?}");
        assert!(!clean.contains(&fullwidth), "{clean:?}");

        // A fullwidth colon-hex dump folds to the ASCII dump and decodes.
        let dump: String = secret
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let fullwidth_dump: String = dump
            .chars()
            .map(|c| char::from_u32(c as u32 + 0xFEE0).unwrap_or(c))
            .collect();
        let text = format!("dump {fullwidth_dump} end");
        let clean = redact_known_secrets(&text).expect("the fullwidth dump must match");
        assert!(clean.contains(MASK), "{clean:?}");
        assert!(!clean.contains(&fullwidth_dump), "{clean:?}");
        clear_known_secrets();
    }
}
