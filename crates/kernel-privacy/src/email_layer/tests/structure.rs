//! Structural-name tests: sequences, particles, bullets and the indexed
//! sequence matcher.

use proptest::prelude::*;

use crate::span::EntityKind;

use super::super::lines::word_tokens;
use super::super::propagate::{mark_sequences, window_matches_any_order};
use super::super::EmailLayer;
use super::{persons, persons_with};

proptest! {
    /// K-REGISTRY-PERF: the indexed pass marks exactly the windows the
    /// old pass, one full scan per sequence, marked.
    #[test]
    fn indexed_sequences_mark_what_one_pass_per_sequence_marked(
        words in prop::collection::vec(prop::sample::select(&WORDS[..]), 0..40),
        seeds in prop::collection::vec(prop::collection::vec(prop::sample::select(&SEED_WORDS[..]), 1..4), 0..8),
    ) {
        let text = words.join(" ");
        let tokens = word_tokens(&text);
        let sequences: Vec<Vec<String>> = seeds
            .iter()
            .map(|seed| seed.iter().map(|word| word.to_string()).collect())
            .collect();
        let mut indexed = vec![false; tokens.len()];
        mark_sequences(&tokens, &text, &sequences, &mut indexed);
        let mut reference = vec![false; tokens.len()];
        for sequence in &sequences {
            for (start, window) in tokens.windows(sequence.len()).enumerate() {
                if window_matches_any_order(sequence, window, &text) {
                    reference[start..start + sequence.len()].fill(true);
                }
            }
        }
        prop_assert_eq!(indexed, reference);
    }
}

/// Text words: full names, initials, structural particles in both cases.
const WORDS: [&str; 12] = [
    "Jean", "jean", "J.", "De", "de", "Le", "D", "Dupont", "dupont", "x", "Mara", "M",
];
const SEED_WORDS: [&str; 6] = ["jean", "de", "le", "dupont", "mara", "marc"];

#[test]
fn a_structural_surname_from_a_strong_seed_propagates_with_its_sequence() {
    for (surname, email) in [
        ("De", "jean.de@example.invalid"),
        ("Le", "jean.le@example.invalid"),
    ] {
        let text = format!(
            "Jean {surname} <{email}>\n\n\
                 merci Jean {surname}\n\
                 M. {surname} a appelé\n\
                 le dossier de Jean"
        );
        let spans = EmailLayer::new().with_first_names(true).analyze(&text);
        let found: Vec<&str> = spans
            .iter()
            .filter(|span| span.kind == EntityKind::Person)
            .map(|span| &text[span.start..span.end])
            .collect();
        let covers = |needle: &str| found.iter().any(|value| value.contains(needle));
        // (a) the full sequence, in the seed order and with the honorific.
        assert!(covers(&format!("Jean {surname}")), "{surname}: {found:?}");
        assert!(covers(&format!("M. {surname}")), "{surname}: {found:?}");
        // (c) the given name always propagates.
        assert!(found.contains(&"Jean"), "{surname}: {found:?}");
        // (b) the lower-case article is never covered by a person span.
        let last_line = text.rfind('\n').map(|at| at + 1).unwrap_or(0);
        let at = last_line
            + text[last_line..]
                .find(&surname.to_lowercase())
                .expect("article");
        assert!(
            !spans
                .iter()
                .any(|span| span.kind == EntityKind::Person && span.start <= at && span.end > at),
            "{surname}: article covered at {at}: {found:?}"
        );
    }
}

#[test]
fn a_structural_surname_sequence_matches_any_order_and_initials() {
    let text = "Jean De <jean.de@example.invalid>\n\nDe Jean, J. De and De J. were here.";
    let found = persons(text);
    for expected in ["De Jean", "J. De", "De J."] {
        assert!(
            found.iter().any(|value| value == expected),
            "{expected:?} in {found:?}"
        );
    }
}

#[test]
fn a_strong_seed_still_propagates_stop_words_and_public_terms() {
    let text = "Will Orange <will.orange@example.invalid>\n\nWill called. Orange left.";
    let found = persons_with(text, true);
    assert!(found.iter().any(|value| value == "Will"), "{found:?}");
    assert!(found.iter().any(|value| value == "Orange"), "{found:?}");
}

#[test]
fn a_surname_from_a_full_seed_still_propagates_alone_with_first_names_off() {
    let text = "Will Orange <will.orange@example.invalid>\n\nWill called. Orange left.";
    let found = persons(text);
    assert!(!found.iter().any(|value| value == "Will"), "{found:?}");
    assert!(found.iter().any(|value| value == "Orange"), "{found:?}");
}

#[test]
fn bullet_and_list_markers_open_a_line_for_a_lone_structural_token() {
    // A structural token after a bullet is not a surname.
    for text in [
        "• le dossier suit",
        "- de la part de Jean",
        "* van het kantoor",
        "> le message",
        "1. le dossier",
        "a) de la part de Jean",
    ] {
        let found = persons(text);
        for label in ["le", "de", "van"] {
            assert!(
                !found.iter().any(|value| value.eq_ignore_ascii_case(label)),
                "bullet line masked {label:?}: {text:?} -> {found:?}"
            );
        }
    }
}

#[test]
fn structural_particles_do_not_propagate_alone() {
    // The particles are structural: a surname particle alone in the text is
    // not a person, but the full name that carries it is.
    let found = persons("van der Berg <van.berg@example.invalid>\n\nvan is here.");
    assert!(
        found.iter().any(|value| value.contains("Berg")),
        "{found:?}"
    );
    assert!(!found.iter().any(|value| value == "van"), "{found:?}");
}
