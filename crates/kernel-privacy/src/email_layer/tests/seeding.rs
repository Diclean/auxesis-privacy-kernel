//! Rule-seeding tests: greetings, sign-offs, headers, speech, line names and
//! tracking links.

use crate::span::EntityKind;

use super::super::EmailLayer;
use super::{persons, persons_with};

#[test]
fn greeting_names_a_full_name_and_propagates() {
    let text = "Bonjour Hugo Dupont,\n\nle dossier suit. Hugo Dupont repondra.";
    let found = persons(text);
    assert!(found.iter().any(|value| value == "Hugo Dupont"));
    assert!(found.iter().filter(|value| *value == "Hugo Dupont").count() >= 2);
}

#[test]
fn a_bare_greeting_name_is_off_by_default_and_on_with_the_switch() {
    let text = "Bonjour Hugo,\n\nle dossier suit. Hugo repondra.";
    assert!(
        persons(text).iter().all(|value| value != "Hugo"),
        "a bare first name was masked by default"
    );
    let found = persons_with(text, true);
    assert!(found.iter().any(|value| value == "Hugo"));
    assert!(found.iter().filter(|value| *value == "Hugo").count() >= 2);
}

#[test]
fn a_surname_from_a_header_propagates_when_a_bare_greeting_name_follows() {
    // The header names the surname, so a later lone `Dupont` is a known
    // surname and still masks; the bare first name `Hugo` does not.
    let text = "De : Hugo Dupont <hugo.dupont@example.invalid>\n\n\
                    Bonjour Hugo,\n\nLe dossier suit.\n\nDupont confirme.";
    let found = persons(text);
    assert!(found.iter().any(|value| value == "Dupont"), "{found:?}");
    assert!(!found.iter().any(|value| value == "Hugo"), "{found:?}");
}

#[test]
fn a_lone_name_after_an_honorific_is_still_masked() {
    let found = persons("Bonjour Dr Hugo,\n\nle dossier suit.");
    assert!(
        found.iter().any(|value| value.contains("Hugo")),
        "{found:?}"
    );
}

#[test]
fn an_all_caps_surname_is_still_masked() {
    let found = persons("Bonjour DUPONT,\n\nle dossier suit.");
    assert!(found.iter().any(|value| value == "DUPONT"), "{found:?}");
}

#[test]
fn sign_off_names_the_next_line() {
    let text = "Merci pour tout,\n\nCordialement,\nThéo Lambrecht";
    let found = persons(text);
    assert!(found.iter().any(|value| value == "Théo Lambrecht"));
}

#[test]
fn ps_author_name_line_is_masked() {
    assert!(persons("C'est tout.\n\nps: Idriss Benali")
        .iter()
        .any(|value| value == "Idriss Benali"));
    // A lone `ps:` author is a bare first name: off by default, on with the
    // switch.
    assert!(persons_with("C'est tout.\n\nps: Idriss", true)
        .iter()
        .any(|value| value == "Idriss"));
}

#[test]
fn sender_header_seeds_propagation_into_a_signature() {
    let text = "De : Océane Mabille <oceane.mabille@example.invalid>\n\
                    Suivi : https://devis.example.invalid/suivi?ref=1\n\
                    Océane Mabille";
    let found = persons(text);
    assert!(found.iter().any(|value| value == "Océane Mabille"));
    // The surname is seeded too, so it is masked inside the URL and the
    // signature as well.
    assert!(found.iter().any(|value| value.contains("Mabille")));
}

#[test]
fn percent_encoded_email_in_a_tracking_link_is_masked() {
    let text = "Shop: https://promo.example.invalid/u?e=freya.halloran%40example.invalid&r=7731";
    let spans = EmailLayer::new().analyze(text);
    let email = spans
        .iter()
        .find(|span| span.kind == EntityKind::Email)
        .expect("email found");
    assert_eq!(
        &text[email.start..email.end],
        "freya.halloran%40example.invalid"
    );
}

#[test]
fn tracking_parameter_value_is_masked_whole() {
    let text = "Click https://x.example.invalid/u?uid=abc123&id=9 now";
    let spans = EmailLayer::new().analyze(text);
    assert!(spans
        .iter()
        .any(|span| span.kind == EntityKind::Person && &text[span.start..span.end] == "abc123"));
}

#[test]
fn name_inside_a_url_path_propagates() {
    let text = "From: Jules Ferrand <jules.ferrand@example.invalid>\n\
                    https://linkedin.example.invalid/in/jules-ferrand";
    let found = persons(text);
    assert!(found.iter().any(|value| value == "jules-ferrand"));
}

#[test]
fn a_lowercase_first_name_propagates_from_a_greeting_when_the_switch_is_on() {
    let text = "hello hugo,\n\nhugo, can you send it?";
    let found = persons_with(text, true);
    assert!(
        found
            .iter()
            .filter(|value| value.as_str() == "hugo")
            .count()
            >= 2
    );
    assert!(persons(text).iter().all(|value| value != "hugo"));
}

#[test]
fn stop_words_never_propagate() {
    assert!(!persons("Bonjour,\nle dossier")
        .iter()
        .any(|value| value == "le"));
}

#[test]
fn a_greeting_names_capitalized_stop_words_and_public_terms() {
    for (text, name) in [
        ("Bonjour Will,\n\nWill, tu viens ?", "Will"),
        ("Bonjour Alice Orange,\n\nOrange a confirmé.", "Orange"),
        ("Bonjour Mark,\n\nMark, voici le dossier.", "Mark"),
        ("Bonjour Pierre,\n\npierre, tu viens ?", "pierre"),
    ] {
        let found = persons_with(text, true);
        let folded = name.to_lowercase();
        let hits = found
            .iter()
            .filter(|value| value.to_lowercase().contains(&folded))
            .count();
        assert!(hits >= 2, "{text:?} -> {found:?}");
    }
}

#[test]
fn colloquial_and_lowercase_greetings_name_a_person() {
    for (text, name) in [
        ("szia Bence,\nköszi", "Bence"),
        ("sziasztok Bence,\nköszi", "Bence"),
        ("helló Bence,\nköszi", "Bence"),
        ("привет Борис,\nспасибо", "Борис"),
        ("здравствуй Борис,\nспасибо", "Борис"),
        ("هلا سامي,\nشكرا", "سامي"),
        ("واخا سامي,\nشكرا", "سامي"),
        ("سلام سامي,\nشكرا", "سامي"),
        ("أهلا سامي,\nشكرا", "سامي"),
        ("hallo Pieter,\ndankie", "Pieter"),
        ("haai Pieter,\ndankie", "Pieter"),
        ("goeie môre Pieter,\ndankie", "Pieter"),
        ("bonjour hugo,\nmerci", "hugo"),
        ("hello hugo,\nthanks", "hugo"),
    ] {
        let found = persons_with(text, true);
        assert!(
            found.iter().any(|value| value == name),
            "{text:?} -> {found:?}"
        );
    }
}

#[test]
fn a_line_initial_name_before_a_comma_is_a_person() {
    // The name directly follows the subject line, in any language. A lone
    // first name is off by default and on with the switch.
    let text = "Objet : dossier\n\nThéo, peux-tu confirmer ?\n\nMerci";
    assert!(persons(text).iter().all(|value| value != "Théo"));
    let found = persons_with(text, true);
    assert!(found.iter().any(|value| value == "Théo"), "{found:?}");
    // A greeting or closing word before the comma is not a name.
    assert!(!persons("Bonjour,\n\nCordialement, Hugo")
        .iter()
        .any(|value| value == "Bonjour"));
}

#[test]
fn an_owner_question_before_a_comma_is_not_a_person() {
    // AGENT-REAL-1: the owner's own questions open with a capitalized word
    // and hold a comma. The short-clause rule must not mask the clause.
    for text in [
            "How many unread mails do I have, and who sent the newest one?",
            "Can you check my calendar, please?",
            "What did Lena say, and when?",
            "Do I have any meetings tomorrow, or is the day free?",
            "Which invoices are still unpaid, and for how long?",
            "Is there anything urgent in my inbox, from this week?",
            "Show me the newest mail, then summarise it.",
            "Who wrote to me yesterday, and what did they want?",
            "Quels mails non lus, et de qui ?",
            "Combien de mails non lus ai-je, et qui a envoyé le dernier ?",
            "Peux-tu vérifier mon agenda, s'il te plaît ?",
            "Est-ce que j'ai une réunion demain, ou la journée est libre ?",
            "Où en est la facture, et quand part-elle ?",
            "Je voudrais voir mes rendez-vous, et les mails liés.",
            // The mail tools' own list lines: the first comma is in the date.
            "uid 12 · Thanks, looks good · from: Jonas Sample <jonas@brightpath.example> · date: Thu, 15 Oct 2026 17:54:55 +0000 · unread · 293 B",
            "Question about the delivery window · from: Camille Example <camille@northwind.example> · date: Thu, 15 Oct 2026 16:54:55 +0000 · unread",
            "Introduction from Camille · date: Thu, 15 Oct 2026 14:54:55 +0000 · unread",
        ] {
            for first_names in [false, true] {
                let found = persons_with(text, first_names);
                let masked_whole_clause = found
                    .iter()
                    .any(|value| value.split_whitespace().count() > 3);
                assert!(
                    !masked_whole_clause && found.iter().all(|value| {
                        matches!(
                            value.as_str(),
                            "Lena" | "Jonas" | "Jonas Sample" | "Camille Example" | "Camille"
                        )
                    }),
                    "{text:?} (first_names={first_names}) -> {found:?}"
                );
            }
        }
    // A real vocative still masks.
    let found = persons_with("Camille, can you send the invoice?", true);
    assert!(found.iter().any(|value| value == "Camille"), "{found:?}");
}

#[test]
fn a_speech_verb_names_its_speaker() {
    for (text, name) in [
        ("Alice said the meeting moved.", "Alice"),
        ("Sabine a dit que le dossier suit.", "Sabine"),
        ("Мария сказала правду.", "Мария"),
        ("Bence azt mondta, hogy kész.", "Bence"),
        ("Pieter het gesê dit is klaar.", "Pieter"),
        ("قال سامي إن الأمر جاهز.", "سامي"),
    ] {
        let found = persons_with(text, true);
        assert!(
            found.iter().any(|value| value == name),
            "{text:?} -> {found:?}"
        );
    }
}

#[test]
fn a_header_label_or_article_is_never_seeded_or_propagated() {
    // `De` and `Le` are structural: the display name seeds only `Monde`,
    // and neither label is masked anywhere, whatever its case.
    let text = "De : Le Monde <contact@example.invalid>\n\n\
                    Le dossier suit, Le Monde confirme.";
    let found = persons(text);
    for label in ["De", "Le", "de", "le"] {
        assert!(
            !found.iter().any(|value| value == label),
            "structural label {label:?} masked: {found:?}"
        );
    }
    assert!(found.iter().any(|value| value == "Monde"), "{found:?}");
}

#[test]
fn a_role_mailbox_never_seeds_its_local_part() {
    for (text, role) in [
        ("Write to contact@example.invalid for the file.", "contact"),
        ("Écris à info@example.invalid pour le dossier.", "info"),
        ("Skryf aan admin@example.invalid vir die lêer.", "admin"),
        ("Írj a compta@example.invalid címre.", "compta"),
    ] {
        let found = persons(text);
        assert!(
            !found.iter().any(|value| value.eq_ignore_ascii_case(role)),
            "role mailbox {role:?} masked: {text:?} -> {found:?}"
        );
    }
    // A real mailbox still seeds its name part, but not a role token.
    let found = persons("Écris à marie.info@example.invalid, marie répondra.");
    assert!(found.iter().any(|value| value == "marie"), "{found:?}");
    assert!(!found.iter().any(|value| value == "info"), "{found:?}");
}
