use super::hits;
use super::UkNinoRecognizer;
use crate::recognizer::Recognizer;

#[test]
fn a_nino_is_masked_spaced_or_glued() {
    assert_eq!(hits("NI AB123456C"), vec!["AB123456C"]);
    assert_eq!(hits("NI AB 12 34 56 C"), vec!["AB 12 34 56 C"]);
    assert_eq!(hits("CE 12 34 56 A"), vec!["CE 12 34 56 A"]);
    assert_eq!(hits("JG123456B"), vec!["JG123456B"]);
    assert_eq!(hits("AB123456D"), vec!["AB123456D"]);
}

#[test]
fn a_nino_with_mixed_spacing_nbsp_or_fullwidth_is_masked() {
    assert_eq!(hits("NI AB 123456 C"), vec!["AB 123456 C"]);
    assert_eq!(hits("NI AB 12 34 56C"), vec!["AB 12 34 56C"]);
    assert_eq!(hits("NI AB12 34 56 C"), vec!["AB12 34 56 C"]);
    assert_eq!(hits("NI AB-12-34-56-C"), vec!["AB-12-34-56-C"]);
    assert_eq!(
        hits("NI AB\u{a0}12\u{a0}34\u{a0}56\u{a0}C"),
        vec!["AB\u{a0}12\u{a0}34\u{a0}56\u{a0}C"]
    );
    assert_eq!(
        hits("NI \u{ff21}\u{ff22}\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff23}"),
        vec!["\u{ff21}\u{ff22}\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff23}"]
    );
}

#[test]
fn a_lowercase_nino_is_masked() {
    assert_eq!(hits("ni ab123456c"), vec!["ab123456c"]);
    assert_eq!(hits("ab 12 34 56 c"), vec!["ab 12 34 56 c"]);
}

#[test]
fn the_hmrc_excluded_prefixes_are_not_masked() {
    for text in [
        "DA123456A",
        "FA123456A",
        "IA123456A",
        "QA123456A",
        "UA123456A",
        "VA123456A",
        "AD123456A",
        "AF123456A",
        "AI123456A",
        "AO123456A",
        "AQ123456A",
        "AU123456A",
        "AV123456A",
        "BG123456A",
        "GB123456A",
        "NK123456A",
        "KN123456A",
        "TN123456A",
        "NT123456A",
        "ZZ123456A",
    ] {
        assert!(hits(text).is_empty(), "{text} is masked");
    }
}

#[test]
fn qq_the_hmrc_example_is_masked() {
    assert_eq!(hits("QQ123456C"), vec!["QQ123456C"]);
    assert_eq!(hits("QQ 12 34 56 C"), vec!["QQ 12 34 56 C"]);
}

#[test]
fn a_suffix_outside_a_to_d_is_not_masked() {
    assert!(hits("AB123456E").is_empty());
}

#[test]
fn a_nino_next_to_an_underscore_or_a_combining_mark_is_masked() {
    assert_eq!(hits("payslip_AB123456C.pdf"), vec!["AB123456C"]);
    assert_eq!(hits("nino_AB123456C"), vec!["AB123456C"]);
    assert_eq!(hits("AB123456C_old"), vec!["AB123456C"]);
    assert_eq!(hits("AB123456C\u{301}"), vec!["AB123456C"]);
}

#[test]
fn a_nino_glued_in_a_word_is_not_masked() {
    assert!(hits("XAB123456C").is_empty());
    assert!(hits("AB123456CX").is_empty());
    assert!(hits("9AB123456C").is_empty());
    assert!(hits("AB1234567C").is_empty());
}

#[test]
fn a_separated_nino_glued_to_letters_when_capital_is_masked() {
    assert_eq!(hits("NI PN.48.15.16.C."), vec!["PN.48.15.16.C"]);
    assert_eq!(hits("qq/12/34/56/a"), vec!["qq/12/34/56/a"]);
    assert_eq!(hits("refQQ/12/34/56/Aok"), vec!["QQ/12/34/56/A"]);
    // Pinned over-mask: a capital pair-and-suffix shape before a word.
    assert_eq!(hits("AB 12 34 56 Cars"), vec!["AB 12 34 56 C"]);
}

#[test]
fn declared_name() {
    assert_eq!(UkNinoRecognizer::new().name(), "uk_nino");
}
