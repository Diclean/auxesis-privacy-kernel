//! Separator runs, line breaks and quoted-printable soft breaks.

use super::super::NormalizedText;

#[test]
fn a_line_break_or_tab_folds_its_run_to_one_separator() {
    assert_eq!(NormalizedText::new("FR76\n3000", false).text(), "FR76 3000");
    assert_eq!(
        NormalizedText::new("FR76\r\n3000", false).text(),
        "FR76 3000"
    );
    assert_eq!(NormalizedText::new("FR76\r3000", false).text(), "FR76 3000");
    assert_eq!(NormalizedText::new("FR76\t3000", false).text(), "FR76 3000");
    // Spaces around the break belong to the same separator.
    assert_eq!(
        NormalizedText::new("FR76 \r\n   3000", false).text(),
        "FR76 3000"
    );
    // Plain spaces keep their behaviour: no break, no fold.
    assert_eq!(
        NormalizedText::new("FR76  3000", false).text(),
        "FR76  3000"
    );
}

#[test]
fn a_folded_break_maps_back_to_its_original_bytes() {
    let text = "x FR76 3000\r\n  0112 y";
    let normalized = NormalizedText::new(text, false);
    let start = normalized.text().find("FR76").expect("normalised value");
    let end = start + "FR76 3000 0112".len();
    let (orig_start, orig_end) = normalized.to_original(start, end).expect("maps back");
    assert_eq!(&text[orig_start..orig_end], "FR76 3000\r\n  0112");
}

#[test]
fn a_quoted_printable_soft_break_joins_the_value_it_wraps() {
    // FAKE: a mail client wrapped a quoted-printable line after the `=`.
    let text = "184030099900=\r\n123";
    let normalized = NormalizedText::new(text, false);
    assert_eq!(normalized.text(), "184030099900123");
    assert_eq!(
        normalized.to_original(0, normalized.text().len()),
        Some((0, text.len()))
    );
}

#[test]
fn a_soft_break_joins_its_sides_with_nothing_between() {
    // FAKE: quoted-printable wraps with LF, CR, CRLF, and blanks before the break.
    for (text, joined) in [
        ("name=\r\n@example.invalid", "name@example.invalid"),
        ("name=\n@example.invalid", "name@example.invalid"),
        ("name=\r@example.invalid", "name@example.invalid"),
        ("na=\r\nme@example.invalid", "name@example.invalid"),
        ("name=  \r\n@example.invalid", "name@example.invalid"),
        ("name=\t\n@example.invalid", "name@example.invalid"),
        ("+33 6 12 3=\r\n4 56 78", "+33 6 12 34 56 78"),
        (
            "FR76 3000 6000 0112 3456 7890 1=\r\n89",
            "FR76 3000 6000 0112 3456 7890 189",
        ),
        ("a=\r\n=\r\nb", "ab"),
    ] {
        assert_eq!(NormalizedText::new(text, false).text(), joined, "{text:?}");
    }
}

#[test]
fn a_plain_equals_sign_is_not_a_soft_break() {
    assert_eq!(NormalizedText::new("a=b", false).text(), "a=b");
    assert_eq!(NormalizedText::new("x = 1", false).text(), "x = 1");
    assert_eq!(NormalizedText::new("id=123", false).text(), "id=123");
    // Nothing or only blanks after the `=`: no break, so nothing is removed.
    assert_eq!(NormalizedText::new("name=", false).text(), "name=");
    assert_eq!(NormalizedText::new("name=  ", false).text(), "name=  ");
    assert_eq!(NormalizedText::new("a= b", false).text(), "a= b");
}

#[test]
fn a_soft_break_maps_back_inside_a_span_that_straddles_it() {
    let text = "mail name=  \r\n@example.invalid, fin";
    let normalized = NormalizedText::new(text, false);
    let start = normalized.text().find("name").expect("local part");
    let end = start + "name@example.invalid".len();
    let (orig_start, orig_end) = normalized.to_original(start, end).expect("maps back");
    assert_eq!(&text[orig_start..orig_end], "name=  \r\n@example.invalid");
}

#[test]
fn soft_break_edges_keep_char_boundaries() {
    // Still-encoded and decoded UTF-8 with the break inside the sequence, and
    // a break or `=` at the very end of the text.
    for (text, normalized) in [
        ("caf=C3=\r\n=A9 ok", "caf=C3=A9 ok"),
        ("café=\r\n@example.invalid", "café@example.invalid"),
        ("é=\r\né=\n", "éé"),
        ("=\r", ""),
        ("=\r\n", ""),
        ("=", "="),
        ("=  ", "=  "),
    ] {
        let view = NormalizedText::new(text, true);
        assert_eq!(view.text(), normalized, "{text:?}");
        if !normalized.is_empty() {
            let (start, end) = view.to_original(0, normalized.len()).expect("maps back");
            assert!(text.is_char_boundary(start) && text.is_char_boundary(end));
        }
    }
}

#[test]
fn a_run_within_the_caps_folds_to_one_space() {
    // Two line breaks and six spaces: eight separator characters.
    assert_eq!(
        NormalizedText::new("FR76\n\n      3000", false).text(),
        "FR76 3000"
    );
    // A CRLF is one line break, so two CRLFs are two breaks.
    assert_eq!(
        NormalizedText::new("FR76\r\n\r\n3000", false).text(),
        "FR76 3000"
    );
}

#[test]
fn a_run_over_the_caps_is_a_hard_boundary() {
    // Three line breaks: a blank paragraph, not a wrap.
    assert_eq!(
        NormalizedText::new("FR76\n\n\n3000", false).text(),
        "FR76\u{0}3000"
    );
    assert_eq!(
        NormalizedText::new("FR76\r\n\r\n\r\n3000", false).text(),
        "FR76\u{0}3000"
    );
    // Two breaks but nine separator characters: over the eight cap.
    assert_eq!(
        NormalizedText::new("FR76\n\n       3000", false).text(),
        "FR76\u{0}3000"
    );
    // Zero-width characters count toward the cap as well.
    let invisible = format!("FR76\n{}3000", "\u{200B}".repeat(8));
    assert_eq!(
        NormalizedText::new(&invisible, false).text(),
        "FR76\u{0}3000"
    );
}

#[test]
fn a_boundary_keeps_the_offset_map_exact() {
    let text = "FR76\n\n\n3000";
    let normalized = NormalizedText::new(text, false);
    let start = normalized.text().find("FR76").expect("left part");
    let (orig_start, orig_end) = normalized.to_original(start, start + 4).expect("maps back");
    assert_eq!(&text[orig_start..orig_end], "FR76");
    let tail = normalized.text().find("3000").expect("right part");
    let (orig_start, orig_end) = normalized.to_original(tail, tail + 4).expect("maps back");
    assert_eq!(&text[orig_start..orig_end], "3000");
}

#[test]
fn a_zero_width_run_over_the_cap_is_a_hard_boundary() {
    // Nine invisible characters and no line break: over the eight cap.
    let invisible = format!("FR76{}3000", "\u{200B}".repeat(9));
    assert_eq!(
        NormalizedText::new(&invisible, false).text(),
        "FR76\u{0}3000"
    );
    // Eight stay within the cap and strip as before.
    let within = format!("FR76{}3000", "\u{200B}".repeat(8));
    assert_eq!(NormalizedText::new(&within, false).text(), "FR763000");
    // Spaces and invisible characters count together.
    let mixed = format!("FR76 {}3000", "\u{200B}".repeat(8));
    assert_eq!(NormalizedText::new(&mixed, false).text(), "FR76\u{0}3000");
}
