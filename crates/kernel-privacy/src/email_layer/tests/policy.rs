//! Policy tests: bare first names, public terms, model singletons, closings and
//! CJK names.

use crate::decode::DecodedText;
use crate::public_terms::PublicTerms;
use crate::span::{EntityKind, Span};

use super::super::signals::ps_marker_end;
use super::super::EmailLayer;
use super::{kept_gliner_person, persons, persons_with};

#[test]
fn public_terms_are_dropped_from_model_org_spans_without_a_private_signal() {
    let layer = EmailLayer::new().with_public_terms(
        PublicTerms::from_json_str(r#"{"en":["Ministry of Transit"]}"#).expect("json"),
    );
    let span = Span::new(EntityKind::Organization, 4, 23, 0.9, "gliner");
    let kept = layer.apply("The Ministry of Transit meets.", vec![span], &[]);
    assert!(kept.is_empty());
    // A person in the text is a private signal: the org span survives. The
    // person is a full name so the bare-first-name rule keeps it.
    let span = Span::new(EntityKind::Organization, 4, 23, 0.9, "gliner");
    let text = "The Ministry of Transit sees Owen Park.";
    let person = Span::new(EntityKind::Person, 29, 38, 0.9, "gliner");
    assert_eq!(&text[29..38], "Owen Park");
    let kept = layer.apply(text, vec![span, person], &[]);
    assert_eq!(kept.len(), 2);
}

#[test]
fn person_spans_are_never_dropped_by_the_allowlist() {
    let layer = EmailLayer::new()
        .with_public_terms(PublicTerms::from_json_str(r#"{"en":["Dublin"]}"#).expect("json"));
    // A two-token person is a full name and survives the allowlist.
    let span = Span::new(EntityKind::Person, 0, 11, 0.9, "gliner");
    let kept = layer.apply("Dublin North", vec![span], &[]);
    assert_eq!(kept.len(), 1);
}

#[test]
fn nbsp_before_a_health_span_is_decoded() {
    let decoded = DecodedText::new("I'm&nbsp;on sick leave");
    assert!(decoded.text().contains("on sick leave"));
}

#[test]
fn dob_in_a_flattened_table_is_found() {
    let text = "Nom\tNé le\tAdresse actuelle\nOcéane Mabille\t12/05/1991\t9 rue X";
    let spans = EmailLayer::new().analyze(text);
    let dob = spans
        .iter()
        .find(|span| span.kind == EntityKind::DateOfBirth)
        .expect("dob");
    assert_eq!(&text[dob.start..dob.end], "12/05/1991");
}

#[test]
fn a_person_seed_beats_stop_words_and_public_terms() {
    let layer = EmailLayer::new().with_first_names(true);
    // "Will" is an English stop word; the seed names it anyway.
    let text = "Will left early. Will was tired.";
    let seed = Span::new(EntityKind::Person, 0, 4, 0.9, "gliner");
    let spans = layer.apply(text, vec![seed], &[seed]);
    assert!(
        spans
            .iter()
            .filter(|span| span.kind == EntityKind::Person)
            .count()
            >= 2,
        "{spans:?}"
    );
    // "Orange" is a built-in public term; as a seeded surname it propagates.
    let text = "Orange called. Orange left a message.";
    let seed = Span::new(EntityKind::Person, 0, 6, 0.9, "gliner");
    let spans = layer.apply(text, vec![seed], &[seed]);
    assert!(
        spans
            .iter()
            .filter(|span| span.kind == EntityKind::Person)
            .count()
            >= 2,
        "{spans:?}"
    );
}

#[test]
fn signature_and_header_singletons_always_stay() {
    // (P1) A lone name in a signature block or a header line is kept, whatever
    // its token count: the bare-first-name policy only bites outside that
    // context.
    for (text, name) in [
        ("Merci,\n\nCordialement,\nMila", "Mila"),
        ("Merci,\n\nCordialement,\n— Mila", "Mila"),
        ("Merci,\n\nCheers,\nMila", "Mila"),
        ("De : Mila <mila@example.invalid>", "Mila"),
        ("From: Mila <mila@example.invalid>", "Mila"),
        ("To: Mila", "Mila"),
        ("Cc: Mila", "Mila"),
        ("发件人: Mila", "Mila"),
        ("Mila wrote:", "Mila"),
        ("Le 2 oct., Mila a écrit :", "Mila"),
    ] {
        assert!(
            kept_gliner_person(text, name, false),
            "{text:?} dropped a signature/header singleton"
        );
    }
    // The sign-off rule itself keeps the singleton too.
    for (text, name) in [
        ("Merci,\n\nCordialement,\nMila", "Mila"),
        ("Merci,\n\nCordialement,\n— Mila", "Mila"),
        ("Merci,\n\nCheers,\nMila", "Mila"),
    ] {
        let found = persons(text);
        assert!(
            found.iter().any(|value| value.contains(name)),
            "{text:?} -> {found:?}"
        );
    }
}

#[test]
fn a_lone_unknown_model_person_is_kept() {
    // (P1) A lone token that may be a surname, a CJK full name or a
    // Hungarian surname-first name stays masked; only a known bare given
    // name is left in clear by default.
    for (text, name) in [
        ("ask Halloran about it", "Halloran"),
        ("Dupont a appelé", "Dupont"),
        ("Martin viendra", "Martin"),
        ("王小明说", "王小明"),
        ("Nagy Bence jött", "Nagy"),
        ("Bonjour Dupont,", "Dupont"),
    ] {
        assert!(
            kept_gliner_person(text, name, false),
            "{text:?} dropped a possible surname"
        );
        assert!(
            kept_gliner_person(text, name, true),
            "{text:?} not masked with mask_first_names"
        );
    }
}

#[test]
fn a_lone_known_given_name_is_left_in_clear_by_default() {
    // The strict rule leaves a lone given name in clear only in a vocative
    // or address position: after a greeting or a thanks word that closes its
    // clause, or at the start of a line followed by a comma. A `P.S.` author
    // is a signature name and is masked (see the table test below).
    for (text, name) in [
        ("Salut Jules", "Jules"),
        ("Hi Mila,", "Mila"),
        ("Hi Mila!", "Mila"),
        ("Salut Mila\n", "Mila"),
        ("thanks Mila", "Mila"),
        ("merci Jules", "Jules"),
        ("Jules, peux-tu", "Jules"),
    ] {
        assert!(
            !kept_gliner_person(text, name, false),
            "{text:?} masked a bare given name by default"
        );
        assert!(
            kept_gliner_person(text, name, true),
            "{text:?} not masked with mask_first_names"
        );
    }
}

#[test]
fn a_lone_given_name_outside_a_vocative_position_is_masked() {
    // (P1) The lexicon alone is not enough: running text, a signature block,
    // a CJK name and a given/surname collision all stay masked, whatever the
    // given-name lexicon says.
    for (text, name) in [
        ("Grace will send the file", "Grace"),
        ("János hívott", "János"),
        ("Mila hívott", "Mila"),
        ("Jules will send the file", "Jules"),
        ("ask Halloran", "Halloran"),
        ("Dupont a appelé", "Dupont"),
        ("Salut Martin", "Martin"),
        ("Mit freundlichen Grüßen\nMila", "Mila"),
        ("此致敬礼\n小明", "小明"),
        // A greeting or thanks word followed by a sentence makes the name its
        // subject, not its addressee.
        ("Hi, Mila was called in today.", "Mila"),
        ("Hello Mila said it was fine.", "Mila"),
        ("merci Jules pour ton aide", "Jules"),
    ] {
        assert!(
            kept_gliner_person(text, name, false),
            "{text:?} left a lone name in clear outside a vocative position"
        );
        assert!(
            kept_gliner_person(text, name, true),
            "{text:?} not masked with mask_first_names"
        );
    }
}

#[test]
fn greeting_and_postscript_repros_hold_in_both_directions() {
    // (P1, security review round 3) After a greeting the name is vocative only when it
    // closes its clause; a sentence after it makes the name the subject. A
    // `P.S.` / `PS` / `NB` author is a signature name, never a vocative. Each
    // case is checked on the rule path (`persons`) and on a lone NER singleton
    // (`kept_gliner_person`).
    for (text, name, clear) in [
        ("Hi Mila,\n\nle dossier suit.", "Mila", true),
        ("Hi Mila!\n\nle dossier suit.", "Mila", true),
        ("Salut Mila\n", "Mila", true),
        ("Hi, Mila was called in today.", "Mila", false),
        ("Hello Mila said it was fine.", "Mila", false),
        ("Bonjour,\n\nP.S. Mila", "Mila", false),
        ("P.S. Mila", "Mila", false),
        ("PS Mila", "Mila", false),
        ("P.S Mila", "Mila", false),
        ("NB Mila", "Mila", false),
    ] {
        let rule_masked = persons(text).iter().any(|value| value.contains(name));
        assert_eq!(
            rule_masked,
            !clear,
            "{text:?} rule path: {:?}",
            persons(text)
        );
        assert_eq!(
            kept_gliner_person(text, name, false),
            !clear,
            "{text:?} NER singleton path"
        );
        assert!(
            kept_gliner_person(text, name, true),
            "{text:?} not masked with mask_first_names"
        );
    }
}

#[test]
fn a_postscript_word_is_not_a_postscript_marker() {
    // `Psychologue` opens with the letters `ps` but is no marker: the name
    // after it is not a signature author. Only the marker boundary decides.
    assert_eq!(ps_marker_end("Psychologue Mila"), None);
    assert_eq!(ps_marker_end("> P.S. Mila"), Some(6));
    assert_eq!(ps_marker_end("NBA Mila"), None);
}

#[test]
fn a_postscript_author_keeps_its_span_when_the_line_has_trailing_space() {
    // The author span must land on the name itself, even when the line ends
    // in spaces or a carriage return: the offset is taken from the full line.
    let text = "P.S. Mila   \r\nà bientôt";
    let found: Vec<&str> = EmailLayer::new()
        .analyze(text)
        .into_iter()
        .filter(|span| span.kind == EntityKind::Person)
        .map(|span| &text[span.start..span.end])
        .collect();
    assert!(found.contains(&"Mila"), "{found:?}");
}

#[test]
fn unknown_rule_tokens_are_never_dropped() {
    // (P1) A rule-detected token the given-name lexicon does not know is
    // masked, never dropped.
    for (text, name) in [
        ("Salut Zorblath", "Zorblath"),
        ("Bonjour Quillfeather,", "Quillfeather"),
        ("Zorblath, peux-tu?", "Zorblath"),
    ] {
        let found = persons_with(text, false);
        assert!(
            found.iter().any(|value| value == name),
            "{text:?} dropped an unknown rule token: {found:?}"
        );
    }
}

#[test]
fn new_closings_open_a_signature_block() {
    // (P1) The added closings and their variants keep the name below them
    // masked, including across an emoji-only or title-only line.
    for closing in [
        "Mit freundlichen Grüßen",
        "Viele Grüße",
        "Liebe Grüße",
        "此致敬礼",
        "此致",
        "敬礼",
        "祝好",
        "顺祝商祺",
        "Met vriendelike groete",
        "Groete",
        "Üdvözlettel",
        "Tisztelettel",
        "Best regards",
        "Kind regards",
        "Regards",
        "Cordialement",
        "Bien à vous",
        "Bisous",
    ] {
        for text in [
            format!("{closing}\nMila"),
            format!("{closing}\n😊\nMila"),
            format!("Best regards\n{closing}\nMila"),
        ] {
            let found = persons_with(&text, false);
            assert!(
                found.iter().any(|value| value == "Mila"),
                "{closing:?} in {text:?} dropped the sign-off name: {found:?}"
            );
            assert!(
                kept_gliner_person(&text, "Mila", false),
                "{text:?} dropped the sign-off NER singleton"
            );
        }
    }
    // A title-only line between the closing and the name is stepped over too.
    let found = persons_with("Best regards\nDr.\nMila", false);
    assert!(found.iter().any(|value| value == "Mila"), "{found:?}");
}

#[test]
fn cjk_person_spans_are_always_kept() {
    for (text, name) in [
        ("王小明说", "王小明"),
        ("김민수 왔다", "김민수"),
        ("李 said hello", "李"),
        ("Dr 王 said hello", "王"),
    ] {
        assert!(
            kept_gliner_person(text, name, false),
            "{text:?} dropped a CJK name"
        );
    }
}
