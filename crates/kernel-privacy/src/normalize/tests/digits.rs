//! Digit values, the OCR confusable fold and the numeric-run helpers.

use super::super::{ascii_digits, numeric_runs, unicode_digit_value, NormalizedText};

#[test]
fn unicode_digits_map_to_ascii() {
    assert_eq!(unicode_digit_value('7'), Some(7));
    assert_eq!(unicode_digit_value('７'), Some(7));
    assert_eq!(unicode_digit_value('٤'), Some(4));
    assert_eq!(unicode_digit_value('a'), None);
    assert_eq!(unicode_digit_value('Ⅷ'), None);
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
