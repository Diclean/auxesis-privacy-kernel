//! Bare Chinese mobile numbers, and the digits that must stay clear.

use super::helpers::masked;
use kernel_privacy::{Anonymizer, EntityKind, Registry};

#[test]
fn bare_chinese_mobile_numbers_are_masked() {
    for (text, number) in [
        ("Mobile 13800138000.", "13800138000"),
        ("手机 13800138000 请回电", "13800138000"),
        ("tel 15912345678", "15912345678"),
        ("138-0013-8000", "138-0013-8000"),
        ("138 0013 8000", "138 0013 8000"),
        ("139.0013.9000", "139.0013.9000"),
    ] {
        let out = masked(text);
        assert!(!out.contains(number), "{number} left in clear: {out}");
    }
}

#[test]
fn a_chinese_mobile_is_masked_whatever_the_words_around_it() {
    for (text, number) in [
        ("Order contact: 138-1234-5678", "138-1234-5678"),
        ("Eating disorder hotline 138-1234-5678", "138-1234-5678"),
        ("Facture client, tél 138 1234 5678", "138 1234 5678"),
        ("订单联系电话：13812345678", "13812345678"),
        ("In order to reach me: 13812345678", "13812345678"),
        ("At the border call 13812345678", "13812345678"),
    ] {
        let out = masked(text);
        assert!(!out.contains(number), "{number} left in clear: {out}");
    }
}

#[test]
fn a_twelve_digit_run_is_not_a_phone() {
    let spans = Registry::new().analyze("138001380001");
    assert!(
        spans.iter().all(|span| span.kind != EntityKind::Phone),
        "phone in a longer digit run: {spans:?}"
    );
}

#[test]
fn a_bare_and_an_international_chinese_mobile_share_one_token() {
    let mut anonymizer = Anonymizer::new([0x4B; 32]);
    let (bare, _) = anonymizer.token_for(EntityKind::Phone, "13800138000");
    let (international, _) = anonymizer.token_for(EntityKind::Phone, "+86 138 0013 8000");
    assert_eq!(bare, international);
}

#[test]
fn an_order_number_with_a_bad_checksum_and_a_phone_stay_clear() {
    for text in ["Commande 110105194912310021 expédiée.", "Tel 13812345678."] {
        let out = masked(text);
        assert!(
            !out.contains("NATIONAL_ID_"),
            "over-masked as an ID: {text} -> {out}"
        );
    }
}
