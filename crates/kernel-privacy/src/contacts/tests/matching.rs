//! Name-variant matching tests: order, case, script, initials and particles.

use crate::recognizer::Recognizer;
use crate::recognizer::Registry;
use crate::span::EntityKind;

use super::super::ContactIndex;
use super::{draft, first_names_masked, masked_by_contacts, masked_kinds};

#[test]
fn every_variant_masks_with_offsets_on_the_source() {
    let mut index = first_names_masked();
    index.add_person(draft(
        "Marie",
        "Dupont",
        &["marie.dupont83@example.invalid"],
    ));
    let text = "Bonjour MARIE, merci à Dupont. Signé M. Dupont, Marie DUPONT, \
                et marie dupont (marie.dupont83 aussi).";
    let found = masked_by_contacts(&index, text);
    let names: Vec<&str> = found.iter().map(|(value, _)| value.as_str()).collect();
    for expected in [
        "MARIE",
        "Dupont",
        "M. Dupont",
        "Marie DUPONT",
        "marie dupont",
        // "(marie" closes the reversed name, which contains the bare given name.
        "dupont (marie",
    ] {
        assert!(names.contains(&expected), "missing {expected}: {names:?}");
    }
    assert!(found.iter().all(|(_, id)| *id == 0));
}

#[test]
fn the_lowercase_and_accented_forms_match() {
    let mut index = first_names_masked();
    index.add_person(draft("Bálint", "Kovács", &[]));
    let found = masked_by_contacts(&index, "szia balint, kovacs úr és BÁLINT KOVÁCS");
    let values: Vec<&str> = found.iter().map(|(value, _)| value.as_str()).collect();
    // "balint, kovacs" is one name; its parts lie inside it.
    assert!(values.contains(&"balint, kovacs"));
    assert!(values.contains(&"BÁLINT KOVÁCS"));
}

#[test]
fn initials_need_upper_case_and_hyphens_match_both_ways() {
    let mut index = first_names_masked();
    index.add_person(draft("Jean-Marc", "Dupont", &[]));
    let found = masked_by_contacts(&index, "JM et jm, J.-M. Dupont, Jean Marc, JeanMarc.");
    let values: Vec<&str> = found.iter().map(|(value, _)| value.as_str()).collect();
    assert!(values.contains(&"JM"));
    assert!(!values.contains(&"jm"));
    assert!(values.contains(&"J.-M. Dupont"));
    assert!(values.contains(&"Dupont, Jean Marc"));
    assert!(values.contains(&"JeanMarc"));
}

#[test]
fn common_words_are_still_masked_for_a_known_person() {
    let mut index = first_names_masked();
    index.add_person(draft("Rose", "Will", &[]));
    let found = masked_by_contacts(&index, "Will you tell Rose? Rosemary is not her.");
    let values: Vec<&str> = found.iter().map(|(value, _)| value.as_str()).collect();
    assert!(values.contains(&"Will"));
    assert!(values.contains(&"Rose"));
    assert!(!values.iter().any(|value| value.starts_with("Rosemary")));
}

#[test]
fn cyrillic_and_arabic_match_in_their_own_script() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Анна", "Смирнова", &[]));
    index.add_person(draft("محمد", "علي", &[]));
    let found = masked_by_contacts(&index, "Привет, анна смирнова! و محمّد علي يرد");
    let values: Vec<&str> = found.iter().map(|(value, _)| value.as_str()).collect();
    assert!(values.contains(&"анна смирнова"));
    assert!(values.contains(&"محمّد علي"));
}

#[test]
fn nicknames_and_registry_union_mask_the_short_form() {
    let mut index = first_names_masked();
    index.add_person(draft("Alexandre", "Morel", &[]));
    let registry = Registry::builder()
        .with_all()
        .with_recognizer(index.recognizer().expect("build"))
        .build();
    let text = "Salut Alex, Alexandre Morel est là.";
    let spans = registry.analyze(text);
    // Another recogniser may join the two names into one region, so check
    // that each name sits inside a masked person span.
    let covered = |needle: &str| {
        let start = text.find(needle).expect("needle is in the text");
        spans.iter().any(|span| {
            span.kind == EntityKind::Person
                && span.start <= start
                && start + needle.len() <= span.end
        })
    };
    assert!(covered("Alex"), "{spans:?}");
    assert!(covered("Alexandre Morel"), "{spans:?}");
}

#[test]
fn a_bare_first_name_is_not_masked_by_default() {
    let mut index = ContactIndex::new();
    assert!(!index.mask_first_names());
    index.add_person(draft("Jules", "Martin", &["jules.martin@example.invalid"]));
    let text = "Jules est là. JULES, Jules Martin, Martin, J. Martin, \
                jules.martin@example.invalid !";
    let found = masked_kinds(&index, text);
    let values: Vec<&str> = found.iter().map(|(_, value)| value.as_str()).collect();
    for expected in ["Jules Martin", "Martin", "J. Martin"] {
        assert!(values.contains(&expected), "missing {expected}: {values:?}");
    }
    assert!(found.contains(&(
        EntityKind::Email,
        "jules.martin@example.invalid".to_string()
    )));
    assert!(
        !values
            .iter()
            .any(|value| value.eq_ignore_ascii_case("jules")),
        "a bare first name was masked: {values:?}"
    );
}

#[test]
fn a_bare_first_name_is_masked_when_first_names_are_on() {
    let mut index = first_names_masked();
    assert!(index.mask_first_names());
    index.add_person(draft("Jules", "Martin", &["jules.martin@example.invalid"]));
    let values: Vec<String> = masked_by_contacts(&index, "Jules est là, et JULES.")
        .into_iter()
        .map(|(value, _)| value)
        .collect();
    assert!(values.contains(&"Jules".to_string()), "{values:?}");
    assert!(values.contains(&"JULES".to_string()), "{values:?}");
}

#[test]
fn spans_are_whole_words_on_char_boundaries() {
    let mut index = first_names_masked();
    index.add_person(draft("Ana", "Ruiz", &[]));
    let text = "Anaïs Ruizzo; Ana.";
    for span in index.recognizer().expect("build").analyze(text) {
        assert!(text.is_char_boundary(span.start) && text.is_char_boundary(span.end));
        assert!(crate::recognizer::span_is_well_formed(text, &span));
    }
    let values: Vec<String> = masked_by_contacts(&index, text)
        .into_iter()
        .map(|(value, _)| value)
        .collect();
    assert_eq!(values, vec!["Ana".to_string()]);
}

#[test]
fn inflected_and_affixed_forms_map_to_exact_spans() {
    let mut index = first_names_masked();
    index.add_person(draft("Анна", "Смирнова", &[]));
    index.add_person(draft("Lilla", "Kovács", &[]));
    index.add_person(draft("علي", "حسن", &[]));
    index.add_person(draft("Jean", "Artagnan", &[]));
    let text = "Письмо Анне Смирновой; Lillának és Lilla-féle; لعلي حسن؛ d'Artagnan.";
    let found: Vec<String> = masked_by_contacts(&index, text)
        .into_iter()
        .map(|(value, _)| value)
        .collect();
    for expected in [
        "Анне Смирновой",
        "Lillának",
        "Lilla-féle",
        "لعلي",
        "d'Artagnan",
    ] {
        assert!(
            found.iter().any(|value| value == expected),
            "missing {expected}: {found:?}"
        );
    }
}

#[test]
fn a_surname_that_is_a_function_word_masks_only_in_name_context() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Marie", "Le", &[]));
    let values = |text: &str| -> Vec<String> {
        masked_by_contacts(&index, text)
            .into_iter()
            .map(|(value, _)| value)
            .collect()
    };
    // Running text: the article "le" is not the surname.
    assert!(values("Le chat est noir, et le meilleur.").is_empty());
    assert!(values("M. le directeur attend. Il faut le dire.").is_empty());
    // Name context: full names, titles, initials, signature and header lines.
    let found = values("Marie Le et Le Marie. M. Le, Mme Le, Mr Le et Dr Le.");
    for expected in ["Marie Le", "Le Marie", "M. Le", "Mme Le", "Mr Le", "Dr Le"] {
        assert!(found.iter().any(|value| value == expected), "{found:?}");
    }
    assert_eq!(values("Merci,\nLe\n"), ["Le"]);
    assert_eq!(values("From: Le\nCc: Paul, Le\n> Le"), ["Le", "Le", "Le"]);
}

#[test]
fn names_split_across_a_line_break_or_in_full_width_match_once() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Jean-Luc", "Martin", &[]));
    index.add_person(draft("Marie", "Dupont", &[]));
    let text = "Jean-Luc\nMartin, signé\nＭＡＲＩＥ　ＤＵＰＯＮＴ et Marie\n  Dupont.";
    let found: Vec<String> = masked_by_contacts(&index, text)
        .into_iter()
        .map(|(value, _)| value)
        .collect();
    assert_eq!(
        found,
        [
            "Jean-Luc\nMartin",
            "ＭＡＲＩＥ　ＤＵＰＯＮＴ",
            "Marie\n  Dupont"
        ]
    );
}

#[test]
fn ligatures_and_final_sigma_match_their_plain_spellings() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Νίκος", "Σάββας", &[]));
    index.add_person(draft("Ana", "Fischer", &[]));
    let text = "ΝΊΚΟΣ ΣΆΒΒΑΣ, Ana \u{FB01}scher.";
    let found: Vec<String> = masked_by_contacts(&index, text)
        .into_iter()
        .map(|(value, _)| value)
        .collect();
    assert_eq!(found, ["ΝΊΚΟΣ ΣΆΒΒΑΣ", "Ana \u{FB01}scher"]);
}

#[test]
fn a_common_word_surname_masks_only_when_capitalised() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Marie", "Rose", &[]));
    let found: Vec<String> = masked_by_contacts(&index, "Rose est là, une rose rouge.")
        .into_iter()
        .map(|(value, _)| value)
        .collect();
    assert_eq!(found, ["Rose"]);
}

#[test]
fn overlapping_contacts_sharing_a_surname_mask_consistently() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Marie", "Dupont", &[]));
    index.add_person(draft("Jean", "Dupont", &[]));
    let found = masked_by_contacts(
        &index,
        "Marie Dupont, Jean Dupont, M. Dupont, J. Dupont, puis Dupont.",
    );
    assert_eq!(
        found,
        [
            ("Marie Dupont".to_string(), 0),
            ("Jean Dupont".to_string(), 1),
            ("M. Dupont".to_string(), 0),
            ("J. Dupont".to_string(), 1),
            ("Dupont".to_string(), 0),
        ]
    );
}

#[test]
fn hyphenated_and_compound_surnames_match_every_spelling() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Claire", "Martin-Dupont", &[]));
    index.add_person(draft("Jan", "van der Berg", &[]));
    let found: Vec<String> = masked_by_contacts(
        &index,
        "Claire Martin-Dupont, CLAIRE MARTIN DUPONT, Martin-Dupont. \
         Jan van der Berg, Jan Van der Berg.",
    )
    .into_iter()
    .map(|(value, _)| value)
    .collect();
    assert_eq!(
        found,
        [
            "Claire Martin-Dupont",
            "Martin-Dupont, CLAIRE",
            "CLAIRE MARTIN DUPONT",
            "Martin-Dupont",
            "Jan van der Berg",
            "van der Berg, Jan",
            "Jan Van der Berg",
        ]
    );
}

#[test]
fn a_family_name_with_particles_also_comes_without_them() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Jean", "de La Fontaine", &[]));
    let found: Vec<String> = masked_by_contacts(&index, "Jean de La Fontaine et La Fontaine.")
        .into_iter()
        .map(|(value, _)| value)
        .collect();
    assert_eq!(found, ["Jean de La Fontaine", "La Fontaine"]);
}
