//! Whole-word matching: case, boundaries, zero-width characters, seals.

use crate::recognizer::{resolve_overlaps, Recognizer};
use crate::span::EntityKind;

use super::super::NameDictionary;
use super::{assert_all, found, spans};

#[test]
fn matches_a_multi_token_name_case_insensitively() {
    let found = resolve_overlaps(spans(
        "Bonjour CAMILLE Exemple, ca va ?",
        &["camille exemple"],
    ));
    assert_eq!(found.len(), 1);
    assert_eq!((found[0].start, found[0].end), (8, 23));
    assert_eq!(found[0].kind, EntityKind::Person);
}

#[test]
fn a_partial_word_is_not_a_match() {
    let dictionary = NameDictionary::new(["Camille"]).expect("dictionary");
    assert!(dictionary.analyze("xcamille").is_empty());
    // A lower-case tail is not a capitalised word, so no tail rule matches.
    assert!(dictionary.analyze("camillefoobar").is_empty());
}

#[test]
fn digits_are_word_boundaries() {
    assert!(found("Camille2024 a écrit", &["Camille Exemple"]));
}

#[test]
fn two_letter_parts_and_particles_follow_the_case_rule() {
    for probe in ["Mme Wu a appelé", "Merci Li", "WU called"] {
        assert!(found(probe, &["Li Wu"]), "{probe:?} matched nothing");
    }
    assert!(
        !found("wu called", &["Li Wu"]),
        "lower-case two-letter part matched without a title"
    );
    assert!(found("Mr Ng will call", &["Ng Ah Kow"]));
    assert!(found("Mme Le Gall", &["Camille Le Gall"]));
    assert!(
        !found("Le dossier est prêt", &["Camille Le Gall"]),
        "a particle alone matched"
    );
    let gall = spans("Mme Le Gall", &["Camille Le Gall"]);
    assert!(gall.iter().any(|span| {
        let value = &"Mme Le Gall"[span.start..span.end];
        value.contains("Le Gall")
    }));
}

#[test]
fn zero_width_inside_a_name_matches() {
    for probe in ["Rapport de Cam\u{AD}ille Exem\u{AD}ple", "Ca\u{200B}mille"] {
        assert!(found(probe, &["Camille Exemple"]), "{probe:?}");
    }
}

#[test]
fn concatenated_runs_match() {
    assert_all(&[
        ("Jean-Pierre Dupont", &["Merci JeanPierre"]),
        ("Camille Le Gall", &["Mme LeGall"]),
        (
            "Marie-Claire de La Fontaine",
            &["Mme DelaFontaine", "Mme DeLaFontaine"],
        ),
        ("Sinéad O'Connor", &["OConnor"]),
    ]);
}

#[test]
fn cyrillic_and_greek_homoglyphs_fold() {
    for probe in ["C\u{430}mille a appelé", "C\u{3B1}mille"] {
        assert!(found(probe, &["Camille"]), "{probe:?}");
    }
}

#[test]
fn every_default_ignorable_is_zero_width() {
    let dictionary = NameDictionary::new(["Camille Exemple"]).expect("dictionary");
    for filler in [
        '\u{2061}',
        '\u{2064}',
        '\u{206F}',
        '\u{180E}',
        '\u{1D173}',
        '\u{E0001}',
        '\u{115F}',
        '\u{3164}',
    ] {
        let probe = format!("Ca{filler}mille");
        assert!(
            !dictionary.analyze(&probe).is_empty(),
            "U+{:04X} did not fold",
            filler as u32
        );
    }
}

#[test]
fn a_particle_that_is_a_name_part_matches_short() {
    assert_all(&[
        ("Ben Martin", &["Merci Ben, à demain"]),
        ("Al Pacino", &["Al called"]),
        ("Thanh Le", &["Thanh and Le went", "LE called yesterday"]),
        ("Van Nguyen", &["Van will join"]),
        ("Abu Bakr", &["Abu said hi"]),
        ("Camille De", &["De called"]),
    ]);
    assert!(!found("Le dossier est prêt", &["Camille Le Gall"]));
}

#[test]
fn every_seal_variant_is_matched() {
    assert_all(&[
        (
            "Camille Exemple",
            &["Bonjour Camille,", "Camille's file", "Camille a appelé"],
        ),
        (
            "Camille Exemple",
            &["Merci Camille", "Mme Exemple a appelé"],
        ),
        ("Camille Exemple", &["C. Exemple", "Camille E."]),
        ("Camille Exemple", &["Exemple Camille", "Exemple, Camille"]),
        (
            "Camille Exemple",
            &["Camille\u{200B}Exemple", "CamilleExemple"],
        ),
        ("Jean-Pierre Dupont", &["JeanPierre Dupont"]),
    ]);
}
