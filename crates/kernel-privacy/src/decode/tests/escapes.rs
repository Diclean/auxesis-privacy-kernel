//! Percent and backslash escapes: what decodes, what stays literal.

use super::super::DecodedText;
use super::decode;

#[test]
fn percent_escapes_decode_only_inside_urls() {
    assert_eq!(
        decode("https://promo.example.invalid/u?e=freya%40example.invalid"),
        "https://promo.example.invalid/u?e=freya@example.invalid"
    );
    // Outside a URL the escape is left alone.
    assert_eq!(decode("just %40 here"), "just %40 here");
    // A multi-byte UTF-8 run decodes to one character.
    assert_eq!(
        decode("https://x.invalid/?nom=Oc%C3%A9ane"),
        "https://x.invalid/?nom=Océane"
    );
}

#[test]
fn percent_bounds_cover_the_escaped_bytes() {
    let source = "https://x.invalid/u?e=freya%40example.invalid";
    let decoded = DecodedText::new(source);
    let at = decoded.text().find('@').expect("decoded at");
    let (begin, end) = decoded.source_bounds(at, at + 1).expect("maps back");
    assert_eq!(&source[begin..end], "%40");
}

#[test]
fn malformed_escapes_stay_literal_and_do_not_hide_valid_ones() {
    // A truncated multi-byte escape is kept whole.
    assert_eq!(
        decode("https://x.invalid/a?n=%E2%8"),
        "https://x.invalid/a?n=%E2%8"
    );
    // A non-hex escape is literal while the valid escapes around it decode.
    assert_eq!(
        decode("https://x.invalid/a?n=%41%ZZ%42"),
        "https://x.invalid/a?n=A%ZZB"
    );
    // A lone `%` stays as written.
    assert_eq!(decode("https://x.invalid/a?n=%"), "https://x.invalid/a?n=%");
}

#[test]
fn a_valid_escape_inside_a_broken_run_still_decodes() {
    let source = "https://x.invalid/u?e=freya%40%E2%8!example.invalid";
    let decoded = DecodedText::new(source);
    assert!(
        decoded.text().contains("freya@%E2%8!example.invalid"),
        "decoded = {}",
        decoded.text()
    );
    // The decoded `@` maps back to the whole broken run, so masking it
    // covers every byte of the run.
    let at = decoded.text().find('@').expect("decoded at");
    let (begin, end) = decoded.source_bounds(at, at + 1).expect("maps back");
    assert_eq!(&source[begin..end], "%40%E2%8");
}

#[test]
fn nested_escapes_unfold_to_a_fixed_point() {
    let source = "https://x.invalid/u?e=freya%2540example.invalid";
    let decoded = DecodedText::new(source);
    assert_eq!(
        decoded.text(),
        "https://x.invalid/u?e=freya@example.invalid"
    );
    // One decoded char maps back to the full doubly encoded escape.
    let at = decoded.text().find('@').expect("decoded at");
    let (begin, end) = decoded.source_bounds(at, at + 1).expect("maps back");
    assert_eq!(&source[begin..end], "%2540");
    // A triple encoding folds too: decoding runs to a fixed point.
    assert_eq!(
        decode("https://x.invalid/u?e=freya%252540example.invalid"),
        "https://x.invalid/u?e=freya@example.invalid"
    );
}
