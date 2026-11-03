//! The common secret shapes and birth contexts are hidden through the gate.
use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::{DetectionReport, EntityKind, Gate};
const KEY: [u8; 32] = [7u8; 32];
fn grant(mode: PrivacyMode) -> Grant {
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, mode, &context) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow for A1 in {mode:?}, got {other:?}"),
    }
}
fn issue(mode: PrivacyMode, text: &str) -> (String, DetectionReport) {
    let mut gate = Gate::for_grant(&grant(mode), KEY);
    let (safe, report) = gate.text(text).expect("the gate issues text");
    (safe.as_str().to_string(), report)
}
/// No needle and no six-character fragment of one may stay readable.
fn hidden(mode: PrivacyMode, text: &str, needles: &[&str], kind: EntityKind) {
    let (out, report) = issue(mode, text);
    for needle in needles {
        assert!(
            !out.contains(needle),
            "{needle:?} readable: {text:?} -> {out:?}"
        );
        for run in needle
            .split_whitespace()
            .filter(|run| run.chars().count() >= 6)
        {
            assert!(!out.contains(run), "fragment {run:?} readable: {out:?}");
        }
    }
    assert!(
        report.count(kind) >= 1,
        "no {kind:?} counted: {text:?} -> {out:?}"
    );
}
#[test]
fn keys_are_hidden_whole() {
    const KEYS: &[&str] = &[
        "NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        "dckr_pat_Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z",
        "key-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z",
    ];
    // Built from parts so push protection does not flag invented fixtures.
    let mut keys: Vec<String> = KEYS.iter().map(|s| s.to_string()).collect();
    keys.push(["glrt-", "Ab3dEf6hIj9kLm2nOp5q"].concat());
    keys.push(
        [
            "doo_v1_",
            "ab3def6c9d2e4f8a1b7c5d3e9f0a2b4c6d8e1f3a5b7c9d0e2f4a6b8c1d3e5f7",
        ]
        .concat(),
    );
    for text in &keys {
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            hidden(mode, text, &[text], EntityKind::Secret);
        }
    }
}
#[test]
fn pem_auth_urls_splits_and_glued_keys_are_hidden() {
    const CASES: &[(&str, &str)] = &[
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA3f\n-----END RSA PRIVATE KEY-----",
            "MIIEowIBAAKCAQEA3f",
        ),
        (
            "https://ada:hunter2-Very-Secret@db.example.invalid/app",
            "hunter2-Very-Secret",
        ),
        (
            "ada:hunter2-Very-Secret@db.example.invalid/app",
            "hunter2-Very-Secret",
        ),
        (
            "ghp_Ab3dEf6hIj9kLm2nOp5q\nRs8tUv1wXy4zAb7cDe0fGh3iJk6lMn",
            "ghp_Ab3dEf6hIj9kLm2nOp5q",
        ),
        (
            "\"sk-ant-api03-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0fGh3iJk6lMn9pQr2sTu5vWx8yZ\",",
            "sk-ant-api03-",
        ),
        (
            "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AKIA",
        ),
        (
            "ASIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "ASIA",
        ),
        (
            "AKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AKIA",
        ),
    ];
    for &(text, value) in CASES {
        let needles: &[&str] = if value == "AKIA" || value == "ASIA" {
            &[
                "AKIAIOSFODNN7EXAMPLE",
                "ASIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ]
        } else {
            &[value]
        };
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            hidden(mode, text, needles, EntityKind::Secret);
        }
    }
}
#[test]
fn secrets_labelled_in_the_six_languages_are_hidden() {
    const LABELS: &[&str] = &[
        "password",
        "mot de passe",
        "wagwoord",
        "jelszó",
        "geslo",
        "密码",
        "API-sleutel",
        "Sleutel",
        "API ključ",
        "Žeton",
        "A jelszavam",
        "API密钥",
    ];
    const VALUE: &str = "hunter2-Very-Secret";
    for label in LABELS {
        for text in [format!("{label}: {VALUE}"), format!("{label}：{VALUE}")] {
            for mode in [PrivacyMode::Private, PrivacyMode::Open] {
                hidden(mode, &text, &[VALUE], EntityKind::Secret);
            }
        }
    }
}
#[test]
fn birth_contexts_in_the_six_languages_are_hidden() {
    const DOB: &[(&str, &str)] = &[
        ("née en 1985 le 3 mars", "1985 le 3 mars"),
        ("b. 1985-03-03", "1985-03-03"),
        ("Gebore op 12 Maart 1984.", "12 Maart 1984"),
        ("Született: 1984. március 12.", "1984. március 12"),
        ("szül. 1984.03.12.", "1984.03.12"),
        ("Rojen 12. marca 1984.", "12. marca 1984"),
        ("出生于1985年3月3日", "1985年3月3日"),
        ("出生日期：1986年4月9日", "1986年4月9日"),
        ("生日是1990年8月6日", "1990年8月6日"),
    ];
    for &(text, value) in DOB {
        hidden(
            PrivacyMode::Private,
            text,
            &[value],
            EntityKind::DateOfBirth,
        );
    }
}
#[test]
fn ordinary_meeting_dates_stay_readable() {
    for text in [
        "Meeting on 3 March 2025.",
        "Réunion le 3 mars 2025.",
        "Vergadering op 12 Maart 2024.",
        "Megbeszélés 2024. március 12-én.",
        "Sestanek 12. marca 2024.",
        "会议日期：2025年3月3日。",
        "Invoice date 12 March 2025",
    ] {
        let (out, report) = issue(PrivacyMode::Private, text);
        assert_eq!(out, text, "a meeting date was masked");
        assert_eq!(report.count(EntityKind::DateOfBirth), 0, "{text:?}");
    }
}
