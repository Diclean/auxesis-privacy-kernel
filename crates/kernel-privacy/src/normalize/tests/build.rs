//! View construction, the shared scan cache and the exact offset map.

use std::sync::Arc;

use proptest::strategy::Strategy as _;

use super::super::view::SHARED;
use super::super::{NormalizedText, SharedViews};

/// K-REGISTRY-PERF: inside a scan a view of its text is the view a fresh
/// build returns, another text is built on its own, and the scan's end
/// forgets the text.
#[test]
fn a_shared_view_is_the_view_a_fresh_build_returns() {
    let text = "Ｏ6 l2\u{200B}34 ＋33\r\n6 12 FR76\n3000 jean＠example．com";
    let fresh = [false, true].map(|ocr| NormalizedText::new(text, ocr));
    let views = SharedViews::new(text);
    for (ocr, fresh) in [false, true].into_iter().zip(&fresh) {
        let shared = NormalizedText::new(text, ocr);
        assert_eq!(shared.text, fresh.text);
        assert_eq!(shared.char_starts, fresh.char_starts);
        assert_eq!(shared.orig_bounds, fresh.orig_bounds);
        assert!(Arc::ptr_eq(
            &shared.text,
            &NormalizedText::new(text, ocr).text
        ));
    }
    assert_eq!(NormalizedText::new("O6 l2", true).text(), "06 12");
    drop(views);
    assert!(SHARED.with(|shared| shared.borrow().depth == 0));
}

fn assert_matches_slow(text: &str, ocr: bool) {
    let fast = NormalizedText::build(text, ocr);
    let slow = NormalizedText::build_slow(text, ocr);
    assert_eq!(fast.text(), slow.text(), "{text:?} ocr={ocr}");
    for start in 0..=text.len() {
        for end in start..=text.len() {
            assert_eq!(
                fast.to_original(start, end),
                slow.to_original(start, end),
                "{text:?} ocr={ocr} {start}..{end}",
            );
        }
    }
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

    #[test]
    fn the_identity_path_matches_the_slow_build_on_ascii(
        bytes in proptest::collection::vec(0x00u8..=0x7f, 0..80),
        ocr in proptest::prelude::any::<bool>(),
    ) {
        let text: String = bytes.into_iter().map(char::from).collect();
        assert_matches_slow(&text, ocr);
    }

    #[test]
    fn the_identity_path_matches_the_slow_build_on_mixed_text(
        chars in proptest::collection::vec(
            proptest::prop_oneof![
                (0x00u8..=0x7f).prop_map(char::from),
                proptest::sample::select(vec![
                    'é', '\u{301}', '\u{200B}', '\u{FF11}', '\u{A0}', '。', '中', '𝐀',
                    '\u{2028}', '\u{85}',
                ]),
            ],
            0..60,
        ),
        ocr in proptest::prelude::any::<bool>(),
    ) {
        let text: String = chars.into_iter().collect();
        assert_matches_slow(&text, ocr);
    }
}

#[test]
fn separators_fold_and_zero_width_is_stripped() {
    let normalized =
        NormalizedText::new("06\u{00A0}12\u{202F}34\u{2010}56\u{2212}78\u{200B}9", true);
    assert_eq!(normalized.text(), "06 12 34-56-789");
}

#[test]
fn fullwidth_digits_are_digits() {
    let normalized = NormalizedText::new("０６ １２ ３４ ５６ ７８", true);
    assert_eq!(normalized.text(), "06 12 34 56 78");
}

#[test]
fn offset_map_returns_original_bytes() {
    let text = "tél : ０６\u{00A0}１２ ３４ ５６ ７８!";
    let normalized = NormalizedText::new(text, true);
    let start = normalized.text().find("06").expect("normalised digits");
    let end = start + "06 12 34 56 78".len();
    let (orig_start, orig_end) = normalized.to_original(start, end).expect("maps back");
    assert_eq!(
        &text[orig_start..orig_end],
        "０６\u{00A0}１２ ３４ ５６ ７８"
    );
}

#[test]
fn fullwidth_letters_and_at_fold() {
    let normalized = NormalizedText::new("ａｐｐ １０.０.０.５", false);
    assert_eq!(normalized.text(), "app 10.0.0.5");
    let mail = NormalizedText::new("ｊｅａｎ＠ｅｘａｍｐｌｅ.ｃｏｍ", false);
    assert_eq!(mail.text(), "jean@example.com");
}

#[test]
fn fullwidth_punctuation_folds_to_ascii() {
    let ip = NormalizedText::new("１９２．１６８．０．１", false);
    assert_eq!(ip.text(), "192.168.0.1");
    let mail = NormalizedText::new("jean＠example．com", false);
    assert_eq!(mail.text(), "jean@example.com");
    let extras = NormalizedText::new("＋－／：（），；", false);
    assert_eq!(extras.text(), "+-/:(),;");
}

#[test]
fn ideographic_stop_folds_only_between_digits() {
    assert_eq!(
        NormalizedText::new("192。168。0。1", false).text(),
        "192.168.0.1"
    );
    // A sentence-ending stop is untouched, so it never becomes a date dot.
    assert_eq!(
        NormalizedText::new("le total 42。", false).text(),
        "le total 42。"
    );
    assert_eq!(NormalizedText::new("。42。", false).text(), "。42。");
}
