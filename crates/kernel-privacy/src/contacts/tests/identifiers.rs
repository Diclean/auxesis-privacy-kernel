//! Identifier matching tests: addresses, phones and IBANs in every spelling.

use crate::recognizer::Recognizer;
use crate::span::EntityKind;

use super::super::{ContactIndex, PersonDraft};
use super::{draft, masked_kinds, zs};

#[test]
fn identifiers_in_every_format_map_to_the_person() {
    let mut index = ContactIndex::new();
    index.add_person(PersonDraft {
        given: zs(&["Marie"]),
        family: zs(&["Dupont"]),
        emails: zs(&["marie.dupont83@example.invalid"]),
        phones: zs(&["+33 6 12 34 56 78"]),
        ibans: zs(&["FR76 3000 6000 0112 3456 7890 189"]),
        ..PersonDraft::default()
    });
    let text = "Écrire à MARIE.DUPONT83@EXAMPLE.INVALID ou 06.12.34.56.78, \
                IBAN FR76 3000 6000\n0112 3456 7890 189.";
    let spans = index.recognizer().expect("build").analyze(text);
    let found: Vec<(EntityKind, &str)> = spans
        .iter()
        .map(|span| (span.kind, &text[span.start..span.end]))
        .collect();
    assert!(found.contains(&(EntityKind::Email, "MARIE.DUPONT83@EXAMPLE.INVALID")));
    assert!(found.contains(&(EntityKind::Phone, "06.12.34.56.78")));
    assert!(found.contains(&(EntityKind::Iban, "FR76 3000 6000\n0112 3456 7890 189")));
    assert!(spans.iter().all(|span| span.person_id == Some(0)));
}

#[test]
fn e_mail_forms_match_in_any_case_and_composition() {
    let mut index = ContactIndex::new();
    index.add_person(draft(
        "Élodie",
        "Martin",
        &["élodie.martin@example.invalid"],
    ));
    let text = "Écrire à ÉLODIE.MARTIN%40EXAMPLE.INVALID, ou E\u{301}LODIE.MARTIN@example.invalid.";
    let emails: Vec<&str> = index
        .recognizer()
        .expect("build")
        .analyze(text)
        .iter()
        .filter(|span| span.kind == EntityKind::Email)
        .map(|span| &text[span.start..span.end])
        .collect();
    assert_eq!(
        emails,
        [
            "ÉLODIE.MARTIN%40EXAMPLE.INVALID",
            "E\u{301}LODIE.MARTIN@example.invalid"
        ]
    );
}

#[test]
fn plus_tags_and_obfuscated_addresses_are_one_email_match() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Jules", "Martin", &["jules@example.invalid"]));
    for (text, expected) in [
        ("jules+crm@example.invalid", "jules+crm@example.invalid"),
        (
            "jules [at] example [dot] invalid",
            "jules [at] example [dot] invalid",
        ),
        (
            "jules(at)example(dot)invalid",
            "jules(at)example(dot)invalid",
        ),
        ("jules%40example%2Einvalid", "jules%40example%2Einvalid"),
        ("mailto:Jules%40Example.invalid", "Jules%40Example.invalid"),
        (
            "JULES AT EXAMPLE DOT INVALID",
            "JULES AT EXAMPLE DOT INVALID",
        ),
        ("jules＠example．invalid", "jules＠example．invalid"),
        ("jul%65s@example.invalid", "jul%65s@example.invalid"),
    ] {
        assert_eq!(
            masked_kinds(&index, text),
            [(EntityKind::Email, expected.to_string())],
            "{text}"
        );
    }
}

#[test]
fn an_iban_in_full_width_or_lower_case_matches() {
    let mut index = ContactIndex::new();
    index.add_person(PersonDraft {
        given: zs(&["Marie"]),
        ibans: zs(&["FR76 3000 6000 0112 3456 7890 189"]),
        ..PersonDraft::default()
    });
    let text = "fr76 3000 6000 0112 3456 7890 189 et ＦＲ７６ ３０００ ６０００ 0112 3456 7890 189";
    let found: Vec<String> = masked_kinds(&index, text)
        .into_iter()
        .filter(|(kind, _)| *kind == EntityKind::Iban)
        .map(|(_, value)| value)
        .collect();
    assert_eq!(
        found,
        [
            "fr76 3000 6000 0112 3456 7890 189",
            "ＦＲ７６ ３０００ ６０００ 0112 3456 7890 189",
        ]
    );
}

#[test]
fn a_stored_address_is_read_in_every_spelling() {
    let mut index = ContactIndex::new();
    index.add_person(PersonDraft {
        given: zs(&["Jules"]),
        emails: zs(&["mailto:Jules%40Example.invalid"]),
        ..PersonDraft::default()
    });
    let found = masked_kinds(&index, "écrire à jules@example.invalid");
    assert_eq!(
        found,
        [(EntityKind::Email, "jules@example.invalid".to_string())]
    );
}

#[test]
fn a_plus_tag_of_a_known_address_names_no_one() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Jules", "Martin", &["jules+crm@example.invalid"]));
    assert!(masked_kinds(&index, "Mon CRM et crm, Jules.").is_empty());
}

#[test]
fn phones_in_every_spelling_map_to_their_contact() {
    let mut index = ContactIndex::new();
    for (given, family, phone) in [
        ("Thandi", "Nkosi", "+27 (0)82 123 4567"),
        ("Anna", "Kovacs", "+36 30 123 4567"),
        ("Li", "Wei", "+86 138 0013 8000"),
        ("Paul", "Local", "06 12 34 56 78"),
    ] {
        index.add_person(PersonDraft {
            phones: zs(&[phone]),
            ..draft(given, family, &[])
        });
    }
    let recognizer = index.recognizer().expect("build");
    let owners = |text: &str| -> Vec<(String, u32)> {
        recognizer
            .analyze(text)
            .into_iter()
            .filter(|span| span.kind == EntityKind::Phone)
            .map(|span| {
                (
                    text[span.start..span.end].to_string(),
                    span.person_id.unwrap_or(u32::MAX),
                )
            })
            .collect()
    };
    for (text, person) in [
        ("082 123 4567", 0),
        ("+27 82 123 4567", 0),
        ("0027 82 123 4567", 0),
        ("+36 30 123 4567", 1),
        ("+36 (0)30 123 4567", 1),
        ("06 30 123 4567", 1),
        ("+86 138 0013 8000", 2),
        ("0086 138 0013 8000", 2),
        ("138 0013 8000", 2),
        ("06 12 34 56 78", 3),
        ("06.12.34.56.78", 3),
    ] {
        assert_eq!(owners(text), [(text.to_string(), person)], "{text}");
    }
    // A local number has no country, so an international form does not match it.
    assert!(owners("+33 6 12 34 56 78").is_empty());
}
