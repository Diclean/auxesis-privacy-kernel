//! EU-KERNEL-1c: Romania, Czechia, Slovakia, Greece and Bulgaria.

use kernel_privacy::recognizers::eu_ids::Eu1cRecognizer;
use kernel_privacy::Recognizer;

use super::helpers::{assert_value_hidden_in_both_modes, spans_of};

/// EU-KERNEL-1c: a CNP whose check fails is not read without a label, and a
/// label hides it. Main's South African rule already removes a bare run of
/// thirteen digits in both modes, so the gate's output is main's business.
#[test]
fn a_romanian_cnp_whose_check_fails_needs_a_label() {
    assert!(spans_of("ro_cnp", "1850709401232").is_empty());
    assert!(!spans_of("ro_cnp", "CNP 1850709401232").is_empty());
    assert_value_hidden_in_both_modes("CNP 1850709401232", "1850709401232");
}

/// EU-KERNEL-1c: a value issued whole and wrapped at the end of a line is
/// still whole, in both modes and without a label.
#[test]
fn a_1c_value_wrapped_at_a_line_end_is_hidden() {
    for (text, value) in [
        ("CZ 855709/\n1235 ok", "855709/\n1235"),
        ("RO 1850709\r\n401231 ok", "1850709\r\n401231"),
        ("GR 090785\n12341 ok", "090785\n12341"),
        ("BG 850709-\n1237 ok", "850709-\n1237"),
    ] {
        assert_value_hidden_in_both_modes(text, value);
    }
    // A break that joins a valid value to more digits is a run more: the
    // value at its head is still read.
    assert_value_hidden_in_both_modes("8507091237-\n42", "8507091237");
}

/// EU-KERNEL-1c: the over-mask of the bare rules on random numbers in prose,
/// with no label: nine to thirteen digits, compact or grouped with the four
/// separators. A rule that read more than its bound would hide too many order
/// numbers, references and timestamps; the AFM and the nine-digit rodné
/// číslo read labels only, so they read none.
#[test]
fn the_1c_rules_rarely_read_a_random_number() {
    const TEXTS: u32 = 50_000;
    let mut seed: u64 = 0x1c1c_2026;
    let mut next = |below: u64| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (seed >> 33) % below
    };
    let rule = Eu1cRecognizer::new();
    let mut hits = std::collections::BTreeMap::<&str, u32>::new();
    for _ in 0..TEXTS {
        let length = 9 + next(5) as usize;
        let digits: String = (0..length)
            .map(|_| char::from(b'0' + next(10) as u8))
            .collect();
        let separator = [' ', '-', '.', '/'][next(4) as usize];
        let number = match next(4) {
            0 | 1 => digits,
            2 => format!("{}{separator}{}", &digits[..6], &digits[6..]),
            _ => digits
                .as_bytes()
                .chunks(3)
                .map(|group| std::str::from_utf8(group).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(&separator.to_string()),
        };
        for span in rule.analyze(&format!("Order {number} is due.")) {
            *hits.entry(span.recognizer).or_default() += 1;
        }
    }
    let rate = |class: &str| f64::from(hits.get(class).copied().unwrap_or(0)) / f64::from(TEXTS);
    println!("over-mask on {TEXTS} random numbers: {hits:?}");
    for (class, bound) in [
        ("ro_cnp", 0.001),
        ("cz_sk_rodne_cislo", 0.003),
        ("gr_afm", 0.0),
        ("gr_amka", 0.001),
        ("bg_egn", 0.003),
    ] {
        assert!(
            rate(class) <= bound,
            "{class}: {:.4} > {bound}",
            rate(class)
        );
    }
}
