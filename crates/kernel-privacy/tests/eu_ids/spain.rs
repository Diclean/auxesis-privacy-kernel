//! Spain: the DNI and the NIE, and the control letter after a separator.

use kernel_privacy::recognizers::eu_ids::EsDniRecognizer;
use kernel_privacy::Recognizer;

use super::helpers::{assert_hidden_in_both_modes, assert_value_hidden_in_both_modes};

/// The Spanish control letter stands after a hyphen, a space, a dot or a
/// single line break, and the NIE keeps its letter before the digits.
#[test]
fn the_spanish_control_letter_may_follow_a_separator() {
    for value in ["12345678-Z", "12345678 Z", "12345678\nZ", "X-1234567-L"] {
        assert_hidden_in_both_modes(value);
        let spans = EsDniRecognizer::new().analyze(value);
        assert!(
            spans
                .iter()
                .any(|span| span.start == 0 && span.end == value.len()),
            "{value:?} -> {spans:?}"
        );
    }
}

/// EU-KERNEL-1b-1: a control letter after a separator, glued to a prose
/// suffix, is the control letter when the check holds.
#[test]
fn a_spanish_control_letter_glued_to_a_suffix_is_read() {
    for (text, value) in [
        ("ref31.415.926-Ltail", "31.415.926-L"),
        ("refY-2456789-Ntail", "Y-2456789-N"),
        ("ref31.415.926-\nLtail", "31.415.926-\nL"),
        ("refY-2456789.Ntail", "Y-2456789.N"),
    ] {
        assert_value_hidden_in_both_modes(text, value);
    }
    // A word after a space is a word: the number stays in clear without a
    // label, and a check that fails never reads a glued word.
    for text in ["invoice 31415926 Lisbon", "ref31.415.926-Mtail"] {
        assert!(EsDniRecognizer::new().analyze(text).is_empty(), "{text:?}");
    }
}
