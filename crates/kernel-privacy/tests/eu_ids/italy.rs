//! Italy: the codice fiscale, its omocodia and the letter of its control
//! character.

use kernel_privacy::recognizers::eu_ids::ItCodiceFiscaleRecognizer;
use kernel_privacy::Recognizer;

use super::helpers::{
    assert_hidden_in_both_modes, assert_value_hidden_in_both_modes, issue, MODES,
};

/// The Italian control character is a letter: the remainder of the odd and
/// even tables stands for the letter `A` to `Z` and never for a digit.
#[test]
fn the_italian_control_character_is_always_a_letter() {
    let value = "AAAAAA00A10H501B";
    assert_hidden_in_both_modes(value);
    // A digit in the place of the control character is not a codice fiscale.
    assert!(
        ItCodiceFiscaleRecognizer::new()
            .analyze("AAAAAA00A10H5011")
            .is_empty(),
        "the rule read a value whose control character is a digit"
    );
}

/// The Italian shape is six letters, two digits, the letter of the month, two
/// digits, the letter of the place, three digits and the control letter; a
/// digit of the omocodia stands for its letter and the check follows.
#[test]
fn the_italian_shape_keeps_three_digits_of_the_place() {
    for value in ["ZMRPKC99R12H780J", "ZMRPKCV9R12H780J"] {
        assert_hidden_in_both_modes(value);
        let spans = ItCodiceFiscaleRecognizer::new().analyze(value);
        assert!(
            spans
                .iter()
                .any(|span| span.start == 0 && span.end == value.len()),
            "{value:?} -> {spans:?}"
        );
    }
}

/// EU-KERNEL-1b-1: a hash is not a codice fiscale. A sixteen-character window
/// of an md5 digest that holds the shape and the check stays in clear in Open
/// mode: masking it corrupts the digest (a #284 over-mask).
#[test]
fn a_hex_digest_is_not_a_codice_fiscale() {
    let digest = "74059780218effbdd55a96c196d8ae89";
    let text = format!("md5 {digest} ok");
    let (output, _) = issue(MODES[1], &text).expect("the gate issues the text");
    assert!(
        output.contains(digest),
        "open mode masked the digest: {output:?}"
    );
    assert!(ItCodiceFiscaleRecognizer::new().analyze(&text).is_empty());
    // A codice fiscale glued to prose is still one.
    assert_value_hidden_in_both_modes("refZMRPKC73R12H780Zok", "ZMRPKC73R12H780Z");
}

/// EU-KERNEL-1b-1: the control letter of an omocodia codice fiscale is
/// computed over the letters as written.
#[test]
fn the_italian_omocodia_check_reads_the_written_letters() {
    for value in ["qrtnvs83d21f20rx", "QRTNVS83D21F20RX"] {
        assert_hidden_in_both_modes(value);
    }
}
