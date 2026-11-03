use super::hits;
use crate::recognizer::Recognizer;
use crate::recognizers::mrz::{PassportMrzRecognizer, STRICT_SCORE};

#[test]
fn masks_separated_unicode_and_case_insensitive_passports() {
    // P1: a single space, hyphen or dot between the prefix and the digits,
    // on the normalised view and case-insensitively.
    assert_eq!(hits("Passport no QXZ 1234567"), vec!["QXZ 1234567"]);
    assert_eq!(hits("جواز السفر QXZ١٢٣٤٥٦٧"), vec!["QXZ١٢٣٤٥٦٧"]);
    assert_eq!(hits("passeport qxz1234567"), vec!["qxz1234567"]);
    assert_eq!(hits("paspoort QXZ-1234567"), vec!["QXZ-1234567"]);
    assert_eq!(hits("passeport l898902c36"), vec!["l898902c36"]);
    // The fullwidth dot and Persian digits fold like their ASCII forms.
    assert_eq!(
        hits("passeport QXZ．１２３４５６７"),
        vec!["QXZ．１２３４５６７"]
    );
    // Two separators are not the passport shape.
    assert!(hits("QXZ  1234567").is_empty());
}

#[test]
fn strict_shape_masks_without_a_cue_and_raises_with_a_check_digit() {
    assert_eq!(hits("reference QXZ1000001"), vec!["QXZ1000001"]);
    let spans = PassportMrzRecognizer::new().analyze("QXZ1000001");
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].score, STRICT_SCORE);
}

#[test]
fn spaced_form_masks_without_a_cue_for_every_prefix_length() {
    // P2: a bare OCR line with no cue at all, for 1, 2 and 3 letter
    // prefixes (`E 12345678` and `AB 1234567` used to leak).
    assert_eq!(hits("QXZ 1234567"), vec!["QXZ 1234567"]);
    assert_eq!(hits("E 12345678"), vec!["E 12345678"]);
    assert_eq!(hits("AB 1234567"), vec!["AB 1234567"]);
    // A 6-digit tail is too weak to stand alone.
    assert!(hits("ISO 123456").is_empty());
    // The two exceptions stay clear: an ISO prefix and a business prefix.
    assert!(hits("ISO 1234567").is_empty());
    assert!(hits("REF 1234567").is_empty());
    // (a) a de-spaced value whose 7-3-1 check digit validates.
    assert_eq!(hits("L 123456781"), vec!["L 123456781"]);
    // A prefix that cues another rule is left to that rule.
    assert!(hits("TAJ 123456788").is_empty());
}

#[test]
fn rejects_all_letter_and_all_digit_shaped_values() {
    assert!(hits("ABCDEFGHI6").is_empty());
    assert!(hits("1234567891").is_empty());
}
