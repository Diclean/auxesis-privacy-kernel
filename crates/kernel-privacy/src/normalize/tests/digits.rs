//! Digit values, the OCR confusable fold and the numeric-run helpers.

use super::super::digits::DIGIT_ZEROS;
use super::super::{ascii_digits, numeric_runs, unicode_digit_value, NormalizedText};

#[test]
fn unicode_digits_map_to_ascii() {
    assert_eq!(unicode_digit_value('7'), Some(7));
    assert_eq!(unicode_digit_value('７'), Some(7));
    assert_eq!(unicode_digit_value('٤'), Some(4));
    assert_eq!(unicode_digit_value('a'), None);
    assert_eq!(unicode_digit_value('Ⅷ'), None);
}

/// Each table entry starts ten numeric chars, in order and without overlap,
/// and every block of the union (broker blocks, Myanmar Extended-C, Tolong
/// Siki) maps to its value.
#[test]
fn digit_table_is_sorted_blocks_of_ten() {
    for pair in DIGIT_ZEROS.windows(2) {
        assert!(
            pair[0] + 10 <= pair[1],
            "U+{:X} overlaps U+{:X}",
            pair[0],
            pair[1]
        );
    }
    for zero in DIGIT_ZEROS {
        for value in 0..10 {
            let ch = char::from_u32(zero + value).expect("valid code point");
            assert!(ch.is_numeric(), "U+{:X} is not numeric", zero + value);
            assert_eq!(unicode_digit_value(ch), Some(value));
        }
    }
    for zero in [
        0x10D40, 0x11950, 0x11BF0, 0x11F50, 0x16130, 0x16AC0, 0x16D70, 0x1CCF0, 0x1E4F0, 0x1E5F1,
        0x116D0, 0x116DA, 0x11DE0,
    ] {
        assert!(DIGIT_ZEROS.contains(&zero), "U+{zero:X} missing");
    }
}

#[test]
fn ocr_fold_only_touches_confusables_beside_digits() {
    let normalized = NormalizedText::new("+33 l 99 OO 41 27", true);
    assert_eq!(normalized.text(), "+33 1 99 00 41 27");
    let leading = NormalizedText::new("O6 l2", true);
    assert_eq!(leading.text(), "06 12");
    let words = NormalizedText::new("I Owe Owen an O", true);
    assert_eq!(words.text(), "I Owe Owen an O");
    // A whole letter word next to a number is not folded (P3-4).
    let after = NormalizedText::new("123456 Ilo om IBAN-ra", true);
    assert_eq!(after.text(), "123456 Ilo om IBAN-ra");
}

#[test]
fn numeric_runs_keep_grouping_and_trim_punctuation() {
    assert_eq!(numeric_runs("x 06 12 34 56 78."), vec![(2, 16)]);
    assert_eq!(ascii_digits("06 12 34 56 78"), "0612345678");
}
