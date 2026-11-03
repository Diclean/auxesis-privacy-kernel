//! The shapes a value takes: glued to prose, wrapped at a separator, or
//! one run more.

use kernel_privacy::recognizers::eu_ids::NlBsnRecognizer;
use kernel_privacy::Recognizer;

use super::helpers::{assert_hidden_in_both_modes, assert_value_hidden_in_both_modes};

/// A value that stands in prose is not part of an opaque token: the length of
/// a token counts its alphanumerics, never the punctuation of the value.
#[test]
fn a_value_glued_to_prose_is_not_an_opaque_token() {
    for (text, value) in [
        ("ref05.03.14-238.79tail", "05.03.14-238.79"),
        ("ref26.954.371.827tail", "26.954.371.827"),
    ] {
        assert_value_hidden_in_both_modes(text, value);
    }
}

/// A run of separators that holds a line break is one separator: a value
/// wrapped after a hyphen or a dot stays one value.
#[test]
fn a_value_wrapped_after_a_separator_stays_one_value() {
    for value in [
        "05.03.14-\n238.79",
        "05.03.14-\r\n238.79",
        "26.954.\n371.827",
        "26.954.\r\n371.827",
    ] {
        assert_hidden_in_both_modes(value);
    }
}

/// The siblings keep their own shape: the Spanish control letter stands after
/// a separator, and the Dutch BSN is nine consecutive digits.
#[test]
fn the_sibling_rules_keep_their_own_shape() {
    // Spain: the value glued to prose, and the value wrapped after a
    // separator: the control letter stands after the one separator, and the
    // NIE keeps its letter before the digits.
    assert_value_hidden_in_both_modes("ref12.345.678Ztail", "12.345.678Z");
    for value in ["12.345.678-\nZ", "12.345.678-\r\nZ", "X-\n1234567L"] {
        assert_hidden_in_both_modes(value);
    }
    // The Netherlands: a BSN glued to prose is still a BSN.
    assert_value_hidden_in_both_modes("ref456789236tail", "456789236");
    // The BSN is issued as nine consecutive digits: a grouped or a wrapped run
    // is a telephone number or a reference, not a BSN. The rule is unchanged.
    for value in ["456 789 236", "45678\n9236"] {
        assert!(
            NlBsnRecognizer::new().analyze(value).is_empty(),
            "{value:?} was read as a BSN"
        );
    }
    // A value that a line break follows keeps its own run: the joined run is a
    // run more, never a run less.
    assert_value_hidden_in_both_modes("26954371827-\n3", "26954371827");
}

/// EU-KERNEL-1b-1: a chain of three runs a line break joins still hides the
/// wrapped value at its head.
#[test]
fn a_wrapped_value_followed_by_more_runs_is_hidden() {
    for (text, value) in [
        ("05.03.14-\n238.79-\n99", "05.03.14-\n238.79"),
        ("26.954.\n371.827-\n12-\n7", "26.954.\n371.827"),
        ("7-\n05.03.14-\n238.79", "05.03.14-\n238.79"),
    ] {
        assert_value_hidden_in_both_modes(text, value);
    }
}
