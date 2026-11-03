//! The person spans: a name grows over the tokens of a full name.

use crate::span::{EntityKind, Span};

use super::super::{extend_hyphenated_persons, Registry};
use super::span;

fn person(text: &str, name: &str) -> Span {
    let start = text.find(name).expect("name in text");
    span(EntityKind::Person, start, start + name.len(), 0.9)
}

fn extended<'a>(text: &'a str, name: &str) -> &'a str {
    let spans = extend_hyphenated_persons(text, vec![person(text, name)]);
    &text[spans[0].start..spans[0].end]
}

#[test]
fn a_hyphenated_surname_is_covered_whole_from_either_half() {
    let text = "Anna Smit-Vosloo called";
    assert_eq!(extended(text, "Anna Smit"), "Anna Smit-Vosloo");
    assert_eq!(extended(text, "Vosloo"), "Smit-Vosloo");
    assert_eq!(
        extended("Hi Jean-Pierre Martin,", "Pierre Martin"),
        "Jean-Pierre Martin"
    );
    assert_eq!(extended("Dear Anna-Halm, the", "Anna"), "Anna-Halm");
}

#[test]
fn hyphen_chains_and_unicode_hyphens_are_followed() {
    let text = "Halm-Berg-Achterberg wrote";
    assert_eq!(extended(text, "Halm"), "Halm-Berg-Achterberg");
    assert_eq!(extended(text, "Achterberg"), "Halm-Berg-Achterberg");
    assert_eq!(
        extended("Smit\u{2010}Vosloo\u{2011}Mor", "Smit"),
        "Smit\u{2010}Vosloo\u{2011}Mor"
    );
    assert_eq!(
        extended("Smit-O\u{2019}Brien x", "Smit"),
        "Smit-O\u{2019}Brien"
    );
}

#[test]
fn hyphen_growth_stops_at_lower_case_digits_spaces_and_addresses() {
    assert_eq!(extended("the Smit-based plan", "Smit"), "Smit");
    assert_eq!(extended("the based-Smit plan", "Smit"), "Smit");
    assert_eq!(extended("Smit-19 and COVID-19", "Smit"), "Smit");
    assert_eq!(extended("2024-Smit", "Smit"), "Smit");
    assert_eq!(extended("Smit - Vosloo", "Smit"), "Smit");
    assert_eq!(extended("Smit-\nVosloo", "Smit"), "Smit");
    assert_eq!(extended("Smit-Vosloo@x.test", "Smit"), "Smit");
}

#[test]
fn only_person_spans_grow_over_a_hyphen() {
    let text = "ACME-Corp pays";
    let org = span(EntityKind::Organization, 0, 4, 0.9);
    let out = extend_hyphenated_persons(text, vec![org]);
    assert_eq!((out[0].start, out[0].end), (0, 4));
}

#[test]
fn the_registry_with_a_dictionary_masks_both_halves() {
    let registry = Registry::builder()
        .with_recognizer(std::sync::Arc::new(
            crate::known_names::NameDictionary::new(["Vosloo", "Anna Smit"]).unwrap(),
        ))
        .build();
    let text = "Hi Smit-Vosloo and Anna Smit-Halm, bye";
    let found = registry.analyze(text);
    let covered: Vec<&str> = found.iter().map(|s| &text[s.start..s.end]).collect();
    assert_eq!(covered, ["Smit-Vosloo", "Anna Smit-Halm"]);
}
