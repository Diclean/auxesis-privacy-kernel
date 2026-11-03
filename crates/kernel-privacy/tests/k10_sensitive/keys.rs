//! API keys and provider key shapes, masked whole.

use super::helpers::masked;
use kernel_privacy::{EntityKind, Registry};

/// Fictional key shapes. Each is built from fragments, so the source holds no
/// whole key-shaped literal. The last one has an IBAN-shaped tail (security-review B).
const KEYS: &[&str] = &[
    concat!("sk-proj-", "FAKEKEY0123456789abcdefGHIJKL"),
    concat!("sk-ant-", "api03-FAKEKEY0123456789abcdefGHIJKL"),
    concat!("sk-", "FAKEKEY0123456789abcdefGHIJKL"),
    concat!("ghp_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"),
    concat!("github_pat_", "FAKEKEY0123456789_abcdefGHIJ"),
    concat!("xoxb-", "0000000000-FAKEKEYFAKEKEY"),
    concat!("AKIA", "FAKEFAKEFAKEFAKE"),
    concat!("AIza", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK"),
    concat!("eyJ", "hbGciFAKE.eyJzdWJFAKE.FAKEsig"),
    concat!("sk-proj-", "FR7630006000011234567890189XYZ"),
];

#[test]
fn api_key_prefixes_are_masked_whole() {
    for key in KEYS {
        let out = masked(&format!("key={key} end"));
        assert!(!out.contains(key), "{key} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {key}: {out}");
        assert!(!out.contains("IBAN_"), "IBAN label on {key}: {out}");
    }
}

#[test]
fn a_short_sk_word_is_not_a_key() {
    for text in ["the sk-learn package", "task-manager-sk-tools"] {
        assert!(!masked(text).contains("SECRET_"), "over-masked: {text}");
    }
}

#[test]
fn a_key_after_han_text_or_an_underscore_is_masked_whole() {
    let anthropic = concat!("sk-ant-", "api03-FAKEKEY0123456789abcdefGHIJKL");
    let aws = concat!("AKIA", "FAKEFAKEFAKEFAKE");
    let cases: [(String, &str); 4] = [
        (format!("我的密钥是{anthropic}"), anthropic),
        (format!("token_{anthropic}"), anthropic),
        (format!("task-{anthropic}"), anthropic),
        (format!("密钥{aws}"), aws),
    ];
    for (text, key) in cases {
        let out = masked(&text);
        assert!(!out.contains(key), "{key} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token: {out}");
        assert!(!out.contains("IBAN_"), "IBAN label on the tail: {out}");
    }
}

#[test]
fn a_secret_wins_over_an_iban_or_a_phone_on_the_same_bytes() {
    for text in [
        "sk-proj-FAKEKEY0123\nFR7630006000011234567890189XYZ",
        "key=sk-proj-FAKEKEY0123456789abcdef13812345678XYZ",
    ] {
        let out = masked(text);
        assert!(out.contains("SECRET_"), "no SECRET token: {out}");
        assert!(!out.contains("IBAN_"), "IBAN label on the key: {out}");
        assert!(!out.contains("PHONE_"), "PHONE label on the key: {out}");
    }
}

#[test]
fn stripe_and_other_issuer_keys_are_masked_whole() {
    let keys = [
        concat!("sk_live_", "FAKEKEY0123456789abcdef"),
        concat!("rk_live_", "FAKEKEY0123456789abcdef"),
        concat!("sk_test_", "FAKEKEY0123456789abcdef"),
        concat!("rk_test_", "FAKEKEY0123456789abcdef"),
        concat!("pk_live_", "FAKEKEY0123456789abcdef"),
        concat!("whsec_", "FAKEKEY0123456789abcdef"),
        concat!("hf_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA"),
        concat!("gsk_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"),
        concat!("glpat-", "FAKEKEY0123456789abcd"),
        concat!("xapp-", "1-FAKEKEY0123-4567890123-abcdef"),
        concat!("ya29.", "FAKEKEY0123456789abcdefGHIJ"),
    ];
    for key in keys {
        let out = masked(&format!("Authorization: Bearer {key} end"));
        assert!(!out.contains(key), "{key} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {key}: {out}");
    }
}

#[test]
fn age_secret_keys_are_masked() {
    let key = concat!(
        "AGE-SECRET-KEY-1",
        "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN"
    );
    let out = masked(&format!("identity {key} end"));
    assert!(!out.contains("QPZRY9"), "age key in clear: {out}");
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
}

#[test]
fn provider_prefixes_are_masked_whole() {
    let telegram = format!("1234567890:AA{}", "FAKEKEY0123456789abcdefGHIJKLmno");
    let keys = [
        concat!("npm_", "FAKEKEY0123456789abcdefGHIJKLmnopqrst").to_string(),
        concat!("pypi-", "AgEIcHlwaS5vcmcFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE").to_string(),
        concat!(
            "SG.",
            "FAKEKEY0123456789ab.FAKEKEY0123456789abcdefGHIJKLmnop"
        )
        .to_string(),
        concat!(
            "dop_v1_",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .to_string(),
        concat!("r8_", "FAKEKEY0123456789abcdefGHIJKLmnopqrst").to_string(),
        concat!("SK", "0123456789abcdef0123456789abcdef").to_string(),
        telegram,
        concat!("lin_api_", "FAKEKEY0123456789abcdefGHIJKLmnopqrs").to_string(),
        concat!("shpat_", "0123456789abcdef0123456789abcdef").to_string(),
        concat!("sbp_", "0123456789abcdef0123456789abcdef01234567").to_string(),
        concat!("ntn_", "FAKEKEY0123456789abcdefGHIJKLmnopqrst").to_string(),
    ];
    for key in keys {
        let out = masked(&format!("token {key} end"));
        assert!(!out.contains(&key), "{key} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {key}: {out}");
    }
}

#[test]
fn a_hyphenated_word_that_starts_with_sk_is_not_a_key() {
    for text in [
        "risk-adjusted-performance-metrics-quarterly-review",
        "task-management-system-for-remote-teams-2025",
    ] {
        let spans = Registry::new().analyze(text);
        assert!(
            spans.iter().all(|span| span.kind != EntityKind::Secret),
            "over-masked as a key: {text}: {spans:?}"
        );
    }
}

#[test]
fn keys_with_zero_width_fullwidth_or_dash_variants_are_masked_whole() {
    let tail = "FAKEKEY0123456789abcdefGHIJKL";
    for text in [
        "key sk-proj-FAKEKEY\u{200B}0123456789abcdefGHIJKL end".to_string(),
        format!("key ｓｋ-ant-api03-{tail} end"),
        format!("key sk\u{2010}proj\u{2010}{tail} end"),
    ] {
        let out = masked(&text);
        assert!(!out.contains("FAKEKEY"), "key left in clear: {out}");
        assert!(
            !out.contains("0123456789"),
            "key digits left in clear: {out}"
        );
        assert!(out.contains("SECRET_"), "no SECRET token: {out}");
    }
}

#[test]
fn issuer_key_shapes_are_masked_whole_and_zoho_is_one_token() {
    let tail = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz0123456789";
    for key in [
        format!("GOCSPX-{}", &tail[..28]),
        format!("EAA{tail}"),
        format!("1//0{tail}"),
        format!("xai-{tail}"),
        format!("pplx-{tail}"),
        format!("hvs.{tail}"),
        format!("tskey-api-{}", &tail[..30]),
        format!("glsa_{tail}"),
        format!("sntrys_{tail}"),
        format!("ATATT3x{tail}"),
        format!("sb_secret_{}", &tail[..30]),
        "shpss_0123456789abcdef0123456789abcdef".to_string(),
        "shpca_0123456789abcdef0123456789abcdef".to_string(),
        "glptt-0123456789abcdef0123456789abcdef01234567".to_string(),
        format!("gldt-{}", &tail[..20]),
        "MTIzNDU2Nzg5MDEyMzQ1Njc4.FAKEKE.FAKEKEY0123456789abcdefGHIJKLmnopq".to_string(),
        "ODEyMzQ1Njc4OTAxMjM0NTY3.GFk3jQ.Fk3jQ9xZ2mP7vB4nL8wRFk3jQ9xZ2mP7vB4nL".to_string(),
    ] {
        let out = masked(&format!("token {key} end"));
        assert!(!out.contains(&key), "{key} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {key}: {out}");
    }
    let zoho = "1000.FAKEKEY0123456789.abcdef0123456789";
    let spans = Registry::new().analyze(&format!("token {zoho} end"));
    let secret: Vec<_> = spans
        .iter()
        .filter(|span| span.kind == EntityKind::Secret)
        .collect();
    assert_eq!(secret.len(), 1, "Zoho token is not one SECRET: {spans:?}");
}

#[test]
fn gitlab_deploy_and_discord_shapes_stay_clear_below_their_format() {
    // A GitLab deploy token is `gldt-` plus 20 characters: 19 is not one.
    let out = masked("deploy: gldt-Fk3jQ9xZ2mP7vB4nL8w");
    assert!(!out.contains("SECRET_"), "a short gldt- was masked: {out}");
    // A Discord bot token's first field starts with M, N or O (user IDs from
    // 8 or 9 encode to OD or OT); any other first letter is not that shape.
    let out = masked("QWERTY1234567890ABCDEFGH.GFk3jQ.Fk3jQ9xZ2mP7vB4nL8wRFk3jQ9xZ2mP7vB4nL");
    assert!(
        !out.contains("SECRET_"),
        "a non-MNO first field was masked: {out}"
    );
}
