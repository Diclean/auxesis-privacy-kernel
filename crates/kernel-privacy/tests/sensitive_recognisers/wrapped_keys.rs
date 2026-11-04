//! Keys that arrive wrapped over several lines.

use super::helpers::{assert_no_window_in_clear, masked};
use kernel_privacy::{EntityKind, Registry};

#[test]
fn a_key_wrapped_at_80_columns_is_masked_whole() {
    let key = format!(
        "sk-proj-{}",
        "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz".repeat(3)
    );
    let wrapped = format!("{}\n{}", &key[..80], &key[80..]);
    let out = masked(&format!("config: {wrapped} end"));
    // No 12-character window of the key may survive in clear, on either line.
    for start in (0..key.len() - 12).step_by(4) {
        let window = &key[start..start + 12];
        assert!(!out.contains(window), "{window} left in clear: {out}");
    }
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
}

#[test]
fn a_key_wrapped_after_a_short_prefix_is_masked() {
    let out = masked("token sk-proj-FAKEKEY0123\nFAKEKEY456789abcdefGHIJKL end");
    assert!(!out.contains("FAKEKEY0123"), "first line in clear: {out}");
    assert!(
        !out.contains("FAKEKEY456789abcdefGHIJKL"),
        "tail in clear: {out}"
    );
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
}

#[test]
fn a_wrapped_key_longer_than_128_bytes_is_one_token() {
    let key = format!(
        "sk-proj-{}",
        "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz".repeat(3)
    );
    let wrapped = format!("{}\n{}", &key[..80], &key[80..]);
    let spans = Registry::new().analyze(&format!("config: {wrapped} end"));
    let secret = spans
        .iter()
        .filter(|span| span.kind == EntityKind::Secret)
        .count();
    assert_eq!(secret, 1, "one key split into {secret} spans: {spans:?}");
}

#[test]
fn a_wrapped_key_with_an_indented_or_quoted_continuation_is_masked() {
    let head = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuv";
    let tail = "wxyzFAKEKEY0123456789TAIL";
    let cases = [
        format!("api_key: sk-proj-{head}\n  {tail} end"),
        format!("> sk-proj-{head}\n> {tail} end"),
        format!("> sk-proj-{head}\n>> {tail} end"),
        format!("sk-proj-{head}\n\"{tail}\" end"),
    ];
    for text in cases {
        let out = masked(&text);
        assert_no_window_in_clear(&out, head);
        assert_no_window_in_clear(&out, tail);
        assert!(out.contains("SECRET_"), "no SECRET token: {out}");
    }
}

#[test]
fn a_short_first_line_followed_by_an_indented_tail_is_masked() {
    let tail = "FAKEKEY0123456789abcdefGHIJKL";
    let out = masked(&format!("sk-proj-FAKEK\n    {tail} end"));
    assert!(!out.contains("FAKEK\n"), "first line left in clear: {out}");
    assert_no_window_in_clear(&out, tail);
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
}

/// A key of `len` bytes built from `fake`, split into lines of `width` bytes.
fn wrap_key(prefix: &str, len: usize, width: usize) -> (String, String) {
    let body: String = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz"
        .chars()
        .cycle()
        .take(len)
        .collect();
    let key = format!("{prefix}{body}");
    let lines: Vec<String> = key
        .as_bytes()
        .chunks(width)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    (key, lines.join("\n"))
}

#[test]
fn a_key_wrapped_at_thirty_columns_over_six_lines_is_masked_whole() {
    let (key, wrapped) = wrap_key("sk-proj-", 172, 30);
    let out = masked(&format!("cfg {wrapped} end"));
    assert_no_window_in_clear(&out, &key);
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
    assert!(
        !out.contains("IBAN_") && !out.contains("PHONE_"),
        "other label on the key: {out}"
    );
}

#[test]
fn a_wrapped_jwt_and_an_sg_key_with_a_dotted_tail_are_masked_whole() {
    let jwt_head = "eyJhbGciOiJIUzI1NiJ9";
    let jwt_tail = ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let out = masked(&format!("token {jwt_head}\n{jwt_tail} end"));
    assert_no_window_in_clear(&out, jwt_head);
    assert_no_window_in_clear(&out, "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV");
    let sg = "SG.FAKEKEY0123456789ab";
    let sg_tail = ".FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz";
    let out = masked(&format!("key {sg}\n{sg_tail} end"));
    assert_no_window_in_clear(&out, sg_tail);
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
}

#[test]
fn a_continuation_with_a_line_prefix_or_trailing_spaces_is_masked() {
    let head = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuv";
    let tail = "wxyzFAKEKEY0123456789TAILTAIL";
    for text in [
        format!("sk-proj-{head}   \n{tail} end"),
        format!("# sk-proj-{head}\n# {tail} end"),
        format!("// sk-proj-{head}\n// {tail} end"),
        format!(" * sk-proj-{head}\n * {tail} end"),
        format!("| sk-proj-{head}\n| {tail} end"),
    ] {
        let out = masked(&text);
        assert_no_window_in_clear(&out, tail);
    }
}

#[test]
fn a_lone_carriage_return_and_the_unicode_line_separators_break_a_key() {
    let tail = "wxyzFAKEKEY0123456789TAILTAIL";
    for sep in ["\r", "\u{2028}", "\u{85}"] {
        let out = masked(&format!("sk-proj-FAKEKEY0123456789abcdef{sep}{tail} end"));
        assert_no_window_in_clear(&out, tail);
    }
}

#[test]
fn a_wrap_longer_than_four_lines_up_to_eight_kilobytes_is_one_key() {
    let (key, wrapped) = wrap_key("sk-proj-", 4800, 400);
    let out = masked(&format!("cfg {wrapped} end"));
    assert_no_window_in_clear(&out, &key[..key.len().min(4000)]);
    assert!(
        !out.contains("IBAN_") && !out.contains("PHONE_"),
        "other label on the key: {out}"
    );
}
