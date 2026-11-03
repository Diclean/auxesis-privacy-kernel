//! The shape of a key body: its tail and its exact length.

use super::helpers::{covered, draw, exact, parse, Rng, BASE62, MODES};

/// K-SK-TAIL: seeded key shapes with random alphanumeric glue and the
/// punctuation/alphanumeric/end boundaries that previously changed the
/// recognizer's match length. Every format has 10,000 invented samples, and
/// the shared exact reader must show the entire key body hidden in both modes.
#[test]
fn glued_openai_key_tails_are_hidden_in_both_modes() {
    const CASES: usize = 100_000;
    let shapes = [("sk-", 48), ("sk-proj-", 48), ("sk-proj-", 64)];
    let letters = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let digits = b"0123456789";
    let mut rng = Rng(0x4B53_4B54_4149_4C31);
    let mut misses = [[0usize; 2]; 3];
    for (shape_index, (prefix, len)) in shapes.into_iter().enumerate() {
        for case in 0..CASES {
            let before = char::from(BASE62[(rng.next() % BASE62.len() as u64) as usize]);
            let mut key_body = draw(&mut rng, BASE62, len);
            // Exercise marked and unmarked tails without changing the exact
            // issuer body length.
            if case % 2 == 0 {
                key_body.replace_range(0..8, "T3BlbkFJ");
            }
            let suffix = match case % 6 {
                0 => "_".to_string(),
                1 => "-".to_string(),
                2 => ".".to_string(),
                3 => char::from(letters[(rng.next() % letters.len() as u64) as usize]).to_string(),
                4 => char::from(digits[(rng.next() % digits.len() as u64) as usize]).to_string(),
                _ => String::new(),
            };
            let text = format!("{before}{prefix}{key_body}{suffix}");
            let start = 1 + prefix.len();
            let end = start + key_body.len();
            for (mode_index, mode) in MODES.into_iter().enumerate() {
                let now = exact(mode, &text);
                misses[shape_index][mode_index] += usize::from(!covered(&parse(&now), start, end));
            }
        }
    }
    assert_eq!(
        misses, [[0; 2]; 3],
        "per-shape Private/Open misses: {misses:?}"
    );
}

/// Round-one regressions: exact-length runs with too little segmentation are
/// secrets in both modes, while the two #231 segmented identifier examples stay
/// clear. Wrapped key offsets include the inserted LF/CRLF bytes exactly.
#[test]
fn glued_exact_lengths_require_segmented_words_and_wrapped_ranges_are_exact() {
    let repeated = "banana".repeat(8);
    let false_clears = [
        format!("notesk-{repeated}"),
        format!("notesk-proj-{repeated}"),
        "xsk-QuarterlyFinancialReportForEuropeanTeamsRiskTo20!".to_string(),
    ];
    for text in &false_clears {
        let key_start = text.find("sk-").unwrap();
        let key_end = text.find('!').unwrap_or(text.len());
        for mode in MODES {
            assert_eq!(
                exact(mode, text),
                format!("{key_start}-{key_end},"),
                "{text}"
            );
        }
    }

    for text in [
        "task-calculateTotalAmountForUserAccountBalanceInEuros2024",
        "risk-assessmentForQuarterlyReportGenerationAndReview2025",
    ] {
        for mode in MODES {
            assert_eq!(exact(mode, text), "", "{mode:?}: {text}");
        }
    }

    for (prefix, body_len) in [("sk-", 48), ("sk-proj-", 48), ("sk-proj-", 64)] {
        for newline in ["\n", "\r\n"] {
            for split in [1, 7, 24, body_len / 2, body_len - 1] {
                let body = format!("{}{}", "A7b".repeat(body_len / 3), "Q".repeat(body_len % 3));
                let key = format!("{prefix}{body}");
                let wrapped = format!(
                    "{}{}{}",
                    &key[..prefix.len() + split],
                    newline,
                    &key[prefix.len() + split..]
                );
                let text = format!("x{wrapped}_word");
                let end = 1 + key.len() + newline.len();
                for mode in MODES {
                    assert_eq!(
                        exact(mode, &text),
                        format!("1-{end},"),
                        "{mode:?}, {prefix}, {newline:?}, split {split}"
                    );
                }
            }
        }
    }

    // The reported byte-25 LF repro, including its clear identifier suffix.
    let body = "A7b".repeat(16);
    let wrapped = format!("{}\n{}", &body[..21], &body[21..]);
    let text = format!("xsk-{wrapped}_word");
    for mode in MODES {
        assert_eq!(exact(mode, &text), "1-53,", "{mode:?}");
    }
}
