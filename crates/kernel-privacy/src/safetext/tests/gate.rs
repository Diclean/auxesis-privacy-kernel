//! Gate behaviour: policies, detection errors, passes, session tokens, and the
//! removal of prohibited values.

use super::*;
use crate::anonymize::{Anonymizer, PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
use crate::safetext::residue::{clear_parts, MASKED_STAND_IN};
use crate::safetext::tokens::{session_token_len, token_ranges, MAX_SESSION_TOKEN_BYTES};
use kernel_core::privacy::GrantPolicy;
use std::collections::BTreeSet;
use std::sync::Arc;

mod timing {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/timing.rs"
    ));
}

#[test]
fn a_detector_error_after_the_export_mask_fails_closed() {
    let detector = FailsLate(NamesClaimed::new(), std::sync::atomic::AtomicUsize::new(0));
    let mut gate = tokenising_gate(KEY, Arc::new(detector));
    let result = gate.text("user,login_password,note\nalice,hunter2,x");
    assert!(
        result.is_err(),
        "{:?}",
        result.map(|(safe, _)| safe.as_str().to_owned())
    );
}

#[test]
fn open_text_is_issued_unchanged_with_a_would_have_masked_report() {
    let mut gate = passthrough_gate();
    let (safe, report) = gate.text("Bonjour, quelle heure est-il ?").unwrap();
    assert_eq!(safe.as_str(), "Bonjour, quelle heure est-il ?");
    assert_eq!(report.label(), DetectionReport::WOULD_HAVE_MASKED);
    assert!(report.is_empty());
    assert_eq!(gate.policy(), GrantPolicy::Passthrough);
}

#[test]
fn passthrough_reports_what_private_would_have_masked_without_a_value() {
    let raw = "elise.vautrin@example.invalid";
    let mut gate = passthrough_gate();
    let (safe, report) = gate.text(&format!("Écris à {raw} demain")).unwrap();
    // Open mode masks nothing…
    assert!(safe.as_str().contains(raw));
    // …but the report names the kind and the count, never the value.
    assert_eq!(report.label(), DetectionReport::WOULD_HAVE_MASKED);
    assert_eq!(report.count(EntityKind::Email), 1);
    assert_eq!(report.total(), 1);
    assert!(!format!("{report:?}").contains(raw));
    assert!(!report.to_string().contains(raw));
    assert!(report.to_string().contains("EMAIL=1"), "{report}");
}

#[test]
fn detected_values_never_reach_the_masked_text() {
    let mut gate = masking_gate();
    let (safe, report) = gate
        .text("Écris à elise.vautrin@example.invalid demain")
        .unwrap();
    assert!(!safe.as_str().contains("elise.vautrin"));
    assert!(safe.as_str().contains("⟦EMAIL_"));
    assert_eq!(report.label(), DetectionReport::MASKED);
    assert_eq!(report.count(EntityKind::Email), 1);
    assert!(!report.to_string().contains("elise.vautrin"));
    assert_eq!(gate.policy(), GrantPolicy::Tokenised);
}

#[test]
fn a_value_report_counts_every_string_leaf_without_a_value() {
    let mut gate = masking_gate();
    let raw = "elise.vautrin@example.invalid";
    let (safe, report) = gate
        .value(&serde_json::json!({ "to": raw, "note": raw }))
        .unwrap();
    assert_eq!(report.count(EntityKind::Email), 2);
    assert!(!format!("{report:?}").contains("elise.vautrin"));
    assert!(!serde_json::to_string(&safe).unwrap().contains(raw));
}

#[test]
fn a_passthrough_gate_refuses_a_tokenising_grant() {
    assert_eq!(
        Gate::for_passthrough(&grant(PrivacyMode::Private)).unwrap_err(),
        GateError::Key
    );
    assert!(Gate::for_passthrough(&grant(PrivacyMode::Open)).is_ok());
}

#[test]
fn the_same_value_gets_the_same_token_within_a_gate() {
    let mut gate = masking_gate();
    let (first, _) = gate.text("mail elise.vautrin@example.invalid").unwrap();
    let (second, _) = gate.text("encore elise.vautrin@example.invalid").unwrap();
    let token = |text: &str| {
        text.split('⟦')
            .nth(1)
            .unwrap()
            .split('⟧')
            .next()
            .unwrap()
            .to_string()
    };
    assert_eq!(token(first.as_str()), token(second.as_str()));
}

#[test]
fn a_new_key_gives_a_new_token() {
    let value = "mail elise.vautrin@example.invalid";
    let mut a = tokenising_gate([1u8; 32], Arc::new(NamesClaimed::new()));
    let mut b = tokenising_gate([2u8; 32], Arc::new(NamesClaimed::new()));
    let a = a.text(value).unwrap().0;
    let b = b.text(value).unwrap().0;
    assert_ne!(a.as_str(), b.as_str());
}

#[test]
fn a_detection_error_issues_nothing() {
    let mut gate = tokenising_gate(KEY, Arc::new(Broken));
    let err = gate.text("anything").unwrap_err();
    assert_eq!(err, GateError::Detect(DetectError::Panicked));
}

/// Finds the word `secret` on the first pass, then reads the first clear
/// character of every residue view as a value of its class.
struct Leaky(EntityKind, AtomicUsize);

impl Leaky {
    fn new(kind: EntityKind) -> Arc<Self> {
        Arc::new(Self(kind, AtomicUsize::new(0)))
    }
}

impl Detector for Leaky {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        let first = self.1.fetch_add(1, Ordering::SeqCst) == 0;
        let found = if first {
            text.find("secret").map(|at| (at, at + "secret".len()))
        } else {
            let at = text.find(|ch: char| !ch.is_whitespace() && ch != MASKED_STAND_IN);
            at.map(|at| (at, at + 1))
        };
        Ok(found
            .map(|(start, end)| vec![Span::new(self.0, start, end, 1.0, "leaky")])
            .unwrap_or_default())
    }

    fn checks_names(&self) -> bool {
        true
    }
}

#[test]
fn a_residue_still_in_clear_after_the_last_round_is_refused() {
    for kind in [EntityKind::NationalId, EntityKind::Phone] {
        let mut gate = tokenising_gate(KEY, Leaky::new(kind));
        let err = gate.text("a b c d secret").unwrap_err();
        assert_eq!(err, GateError::Residue, "{kind:?}");
    }
}

/// FIN-5: a residue of any class is masked, never refused. Any class but a
/// secret is masked as its own bytes, as its own class.
#[test]
fn a_residue_of_any_class_is_masked_not_refused() {
    for kind in [EntityKind::NationalId, EntityKind::Phone, EntityKind::Iban] {
        let mut gate = tokenising_gate(KEY, Leaky::new(kind));
        let (safe, _) = gate.text("a secret").unwrap();
        let clear = clear_parts(safe.as_str());
        assert!(
            clear
                .chars()
                .all(|ch| ch == MASKED_STAND_IN || ch.is_whitespace()),
            "{kind:?}: {}",
            safe.as_str()
        );
    }
}

#[test]
fn a_secret_residue_is_masked_to_its_line_end_not_refused() {
    let mut gate = tokenising_gate(KEY, Leaky::new(EntityKind::Secret));
    let (safe, _) = gate.text("a b secret\nnext").unwrap();
    assert!(safe.as_str().starts_with('⟦'), "{}", safe.as_str());
    assert!(!safe.as_str().contains("a b"), "{}", safe.as_str());
    // Each round masks one more line; past the last round the gate refuses.
    let mut gate = tokenising_gate(KEY, Leaky::new(EntityKind::Secret));
    let text = "a\nb\nc\nd\nsecret";
    assert_eq!(gate.text(text).unwrap_err(), GateError::Residue);
}

#[test]
fn session_tokens_pass_whole_and_clear_values_are_masked() {
    let mut gate = Gate::for_session_tokens(&grant(PrivacyMode::Private), minted()).unwrap();
    let input = serde_json::json!({
        "to": "⟦EMAIL_0A1B2C3D4E5F⟧",
        "note": "iban ⟦IBAN_0A1B2C3D4E5F_2⟧ or elise.vautrin@example.invalid",
        "forged": "⟦FR7630006000011234567890189⟧"
    });
    let (safe, _) = gate.value(&input).unwrap();
    let wire = serde_json::to_string(&safe).unwrap();
    assert!(wire.contains("\"⟦EMAIL_0A1B2C3D4E5F⟧\""), "{wire}");
    assert!(wire.contains("⟦IBAN_0A1B2C3D4E5F_2⟧"), "{wire}");
    assert!(!wire.contains("elise.vautrin"), "{wire}");
    assert!(!wire.contains("FR7630006000011234567890189"), "{wire}");
}

/// A kept session token can leave detection with nothing, but the residue
/// pass still reads the password label after it: the next line is masked.
#[test]
fn a_minted_token_before_a_password_label_does_not_skip_the_residue_pass() {
    let mut gate = Gate::for_session_tokens(&grant(PrivacyMode::Private), minted()).unwrap();
    let (safe, _) = gate
        .text("prefix ⟦EMAIL_0A1B2C3D4E5F⟧password\nordinaryword")
        .expect("the residue pass masks the value");
    assert!(!safe.as_str().contains("ordinaryword"), "{}", safe.as_str());
}

/// The tokens this test's session minted.
fn minted() -> Arc<BTreeSet<String>> {
    Arc::new(
        [
            "EMAIL_0A1B2C3D4E5F",
            "IBAN_0A1B2C3D4E5F_2",
            "PERSON_0A1B2C3D4E5F",
        ]
        .map(String::from)
        .into(),
    )
}

fn session_gate_wire(input: &str) -> String {
    let mut gate = Gate::for_session_tokens(&grant(PrivacyMode::Private), minted()).unwrap();
    let (safe, _) = gate.value(&serde_json::json!({ "v": input })).unwrap();
    serde_json::to_string(&safe).unwrap()
}

#[test]
fn a_kept_session_token_stays_a_reference_and_clear_values_are_still_masked() {
    let mut gate = Gate::for_grant(&grant(PrivacyMode::Private), [3u8; 32]);
    let (first, _) = gate.text("Write to anne@example.org").unwrap();
    let minted = gate.take_minted();
    let token = minted[0].0.clone();
    assert!(first.as_str().contains(&format!("⟦{token}⟧")));
    let reply = format!("Mail from ⟦{token}⟧, cc bob@example.org.");

    // By default a token-shaped string the model wrote is literal text.
    let (plain, _) = gate.text(&reply).unwrap();
    assert!(
        plain.as_str().contains(&format!("⟦⟦{token}⟧")),
        "{}",
        plain.as_str()
    );
    gate.take_minted();

    gate.keep_session_tokens(Some(Arc::new([token.clone()].into())));
    let (kept, _) = gate.text(&reply.replace("bob", "carol")).unwrap();
    assert!(kept
        .as_str()
        .starts_with(&format!("Mail from ⟦{token}⟧, cc ⟦EMAIL_")));
    assert!(!kept.as_str().contains("carol@example.org"));
    let new = gate.take_minted();
    assert_eq!(
        new.len(),
        1,
        "the clear value is minted under the session key"
    );
    assert_eq!(new[0].1, "carol@example.org");

    gate.keep_session_tokens(None);
    assert!(gate.text(&reply).unwrap().0.as_str().contains("⟦⟦"));

    // Open mode: a passthrough gate ignores it and keeps the text.
    let mut open = Gate::for_passthrough(&grant(PrivacyMode::Open)).unwrap();
    open.keep_session_tokens(Some(Arc::new([token.clone()].into())));
    assert_eq!(open.text(&reply).unwrap().0.as_str(), reply);
}

#[test]
fn kept_tokens_are_found_in_linear_time_on_openers_with_no_closer() {
    // A model reply of `⟦x` repeated: 1 MiB and no closer. A closer search
    // to the end of the text at each opener took 8 s in release; one pass is
    // milliseconds (7 ms release). The bound is generous for a debug build.
    let text = "⟦x".repeat(1024 * 1024 / 4);
    let issued = minted();
    // The fastest of nine runs, after one warm-up: the bound is on the work,
    // not on the scheduler.
    let scan = timing::fastest(|| {
        assert!(token_ranges(&text, &issued).is_empty());
    });
    assert!(scan < std::time::Duration::from_secs(2), "{scan:?}");
    // A closer past the longest token is not read as one.
    let far = format!("⟦{}_0A1B2C3D4E5F⟧", "K".repeat(MAX_SESSION_TOKEN_BYTES));
    assert_eq!(session_token_len(&far), None);
    assert!(session_token_len("⟦EMAIL_0A1B2C3D4E5F⟧ rest").is_some());
}

#[test]
fn only_standalone_known_issued_tokens_are_kept() {
    let token = "EMAIL_0A1B2C3D4E5F";
    let issued: Arc<BTreeSet<String>> = Arc::new([token.to_string()].into());
    let malformed_contexts = [
        format!("⟦X⟦{token}⟧Y⟧"),
        format!("&#10214;X ⟦{token}⟧Y&#10215;"),
    ];
    for text in malformed_contexts {
        assert!(
            token_ranges(&text, &issued).is_empty(),
            "nested or encoded marker was treated as issued: {text:?}"
        );
    }

    let unknown: Arc<BTreeSet<String>> = Arc::new(["UNKNOWN_0A1B2C3D4E5F".to_string()].into());
    assert!(
        token_ranges("⟦UNKNOWN_0A1B2C3D4E5F⟧", &unknown).is_empty(),
        "an unknown label is not a kernel token"
    );
    let standalone = token_ranges(&format!("⟦{token}⟧"), &issued);
    assert_eq!(standalone.len(), 1);
}

#[test]
fn many_mixed_issued_markers_are_scanned_within_a_linear_bound() {
    const TARGET_BYTES: usize = 1024 * 1024;
    let token = "EMAIL_0A1B2C3D4E5F";
    let issued_marker = format!("⟦{token}⟧");
    let unknown_marker = "⟦EMAIL_FFFFFFFFFFFF⟧";
    let nested_marker = format!("⟦X{issued_marker}Y⟧");
    let mut text = String::with_capacity(TARGET_BYTES);
    let mut expected = 0;
    while text.len() < TARGET_BYTES {
        for _ in 0..16 {
            text.push_str(&issued_marker);
            text.push(' ');
            expected += 1;
        }
        text.push_str(unknown_marker);
        text.push(' ');
        text.push_str(&nested_marker);
        text.push(' ');
    }
    let issued: BTreeSet<String> = [token.to_string()].into();

    let ranges = token_ranges(&text, &issued);
    // The fastest of nine runs, after one warm-up: the bound is on the work,
    // not on the scheduler.
    let elapsed = timing::fastest(|| {
        let _ = token_ranges(&text, &issued);
    });

    assert_eq!(
        ranges.len(),
        expected,
        "only standalone issued markers pass"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "1 MiB with {expected} issued markers took {elapsed:?}"
    );
}

#[test]
fn standalone_issued_tokens_still_rehydrate() {
    let key = format!("sk-proj-{}", "Ab9cD2eF7gH4iJ1kL8mN5pQ3rS6tU0vW9xY2zA4b");
    let mut anonymizer = Anonymizer::new(KEY);
    let span = Span::new(EntityKind::Secret, 0, key.len(), 1.0, "test");
    let (issued, pairs) = anonymizer.anonymize(&key, &[span]);
    let token = issued
        .strip_prefix(PLACEHOLDER_OPEN)
        .and_then(|body| body.strip_suffix(PLACEHOLDER_CLOSE))
        .expect("one token marker")
        .to_string();
    let mut gate =
        Gate::for_session_tokens(&grant(PrivacyMode::Private), Arc::new([token].into())).unwrap();
    let (safe, _) = gate.text(&issued).unwrap();
    assert_eq!(safe.as_str(), issued);
    assert_eq!(
        Anonymizer::restore(safe.as_str(), &pairs, crate::anonymize::UnknownPolicy::Keep).text,
        key
    );
}

#[test]
fn a_forged_token_cannot_split_an_email_out_of_detection() {
    let wire = session_gate_wire("mara@⟦EMAIL_0123456789AB⟧example.test");
    assert!(!wire.contains("mara@"), "{wire}");
    assert!(!wire.contains("example.test"), "{wire}");
    // Deleting the forged token must not give the server the address.
    let stripped = wire.replace("⟦EMAIL_0123456789AB⟧", "");
    assert!(!stripped.contains("mara@example.test"), "{stripped}");
}

#[test]
fn a_forged_token_next_to_an_iban_does_not_hide_it() {
    let wire = session_gate_wire("⟦IBAN_0123456789AB⟧FR7630006000011234567890189");
    assert!(!wire.contains("FR7630006000011234567890189"), "{wire}");
    let wire = session_gate_wire("FR76300060⟦IBAN_0123456789AB⟧00011234567890189");
    assert!(!wire.contains("00011234567890189"), "{wire}");
    assert!(!wire.contains("FR76300060"), "{wire}");
}

#[test]
fn a_real_session_token_beside_a_raw_value_stays_and_the_value_is_masked() {
    let wire = session_gate_wire("⟦PERSON_0A1B2C3D4E5F⟧mara@example.test");
    assert!(wire.contains("⟦PERSON_0A1B2C3D4E5F⟧"), "{wire}");
    assert!(!wire.contains("mara@example.test"), "{wire}");
    let wire = session_gate_wire("mara@example.test⟦PERSON_0A1B2C3D4E5F⟧");
    assert!(wire.contains("⟦PERSON_0A1B2C3D4E5F⟧"), "{wire}");
    assert!(!wire.contains("mara@example.test"), "{wire}");
}

#[test]
fn look_alike_brackets_are_not_tokens() {
    for (open, close) in [("〚", "〛"), ("［", "］"), ("❬", "❭"), ("⟦\u{200B}", "⟧")] {
        let token = format!("{open}PERSON_0A1B2C3D4E5F{close}");
        let wire = session_gate_wire(&format!("{token}mara@example.test"));
        assert!(!wire.contains("mara@"), "{token}: {wire}");
        let wire = session_gate_wire(&format!("{token}FR7630006000011234567890189"));
        assert!(
            !wire.contains("FR7630006000011234567890189"),
            "{token}: {wire}"
        );
    }
    // A token spelled with look-alike brackets is not the session's: the
    // text around it is masked exactly as if it were absent.
    let wire = session_gate_wire("〚PERSON_0A1B2C3D4E5F〛");
    assert!(!wire.contains("⟦PERSON_0A1B2C3D4E5F⟧"), "{wire}");
}

#[test]
fn a_token_the_session_never_minted_is_masked_like_text() {
    let wire = session_gate_wire("⟦EMAIL_FFFFFFFFFFFF⟧ and ⟦EMAIL_0A1B2C3D4E5F⟧");
    assert!(wire.contains(" ⟦EMAIL_0A1B2C3D4E5F⟧"), "{wire}");
    // Plain text: its opener is escaped, as for any typed `⟦`.
    assert!(wire.contains("⟦⟦EMAIL_FFFFFFFFFFFF⟧"), "{wire}");
    // An escaped opener is a literal one, never a token.
    let wire = session_gate_wire("⟦⟦EMAIL_0A1B2C3D4E5F⟧");
    assert!(wire.contains("⟦⟦⟦⟦EMAIL_0A1B2C3D4E5F⟧"), "{wire}");
}

#[test]
fn foreign_token_text_is_scanned_but_minted_tokens_are_kept() {
    // `AB12…` has an IBAN anchor. A foreign marker is plain text and can
    // be masked; only a marker in this session's issued set stays opaque.
    let mut private = Gate::for_grant(&grant(PrivacyMode::Private), KEY);
    let mut open = Gate::for_passthrough(&grant(PrivacyMode::Open)).unwrap();
    for token in ["PERSON_AB12CDEFABCD", "PERSON_AB12CDEFABCD_2"] {
        for text in [
            format!("find mail from ⟦{token}⟧"),
            format!("find mail from ⟦⟦{token}⟧"),
        ] {
            let wire = session_gate_wire(&text);
            let (plain, _) = private.text(&text).unwrap();
            let (shown, _) = open.text(&text).unwrap();
            for out in [wire.as_str(), plain.as_str(), shown.as_str()] {
                assert!(!out.contains(token), "foreign marker escaped: {out}");
            }
        }
    }
    let issued = session_gate_wire("find mail from ⟦PERSON_0A1B2C3D4E5F⟧");
    assert!(issued.contains("⟦PERSON_0A1B2C3D4E5F⟧"), "{issued}");
    assert!(!issued.contains("IBAN"), "{issued}");
    // A value a foreign token splits is still read whole.
    let (plain, _) = private
        .text("FR76300060⟦IBAN_0123456789AB⟧00011234567890189")
        .unwrap();
    assert!(
        !plain.as_str().contains("00011234567890189"),
        "{}",
        plain.as_str()
    );
}

#[test]
fn a_card_or_id_hidden_in_a_fake_token_suffix_is_still_masked() {
    let mut private = Gate::for_grant(&grant(PrivacyMode::Private), KEY);
    for text in [
        "pay with ⟦CARD_AAAAAAAAAAAA_4111111111111111⟧ now",
        "pay with ⟦⟦CARD_AAAAAAAAAAAA_4111111111111111⟧ now",
        "iban ⟦PERSON_AB12CDEFABCD_FR7630006000011234567890189⟧ ok",
    ] {
        let (plain, _) = private.text(text).unwrap();
        assert!(
            !plain.as_str().contains("4111111111111111"),
            "{}",
            plain.as_str()
        );
        assert!(
            !plain.as_str().contains("30006000011234567890189"),
            "{}",
            plain.as_str()
        );
    }
}

#[test]
fn a_span_that_touches_a_real_token_masks_the_token_whole() {
    let wire = session_gate_wire("mara@⟦EMAIL_0A1B2C3D4E5F⟧example.test");
    assert!(!wire.contains("EMAIL_0A1B2C3D4E5F"), "{wire}");
    assert!(!wire.contains("example.test"), "{wire}");
}

#[test]
fn a_passthrough_grant_cannot_build_a_session_token_gate() {
    assert!(Gate::for_session_tokens(&grant(PrivacyMode::Open), minted()).is_err());
}
