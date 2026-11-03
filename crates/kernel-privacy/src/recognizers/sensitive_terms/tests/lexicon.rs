//! Lexicon rows, abbreviations and their excepted words.

use std::collections::HashSet;

use super::super::inflect::{hungarian_stem, slovene_stem, Inflection, Token};
use super::super::lexicon::{parse_line, DATA};
use super::super::text::fold_str;
use super::hits;

#[test]
fn every_lexicon_line_is_well_formed() {
    for (number, line) in DATA.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert!(
            parse_line(line).is_some(),
            "lexicon line {} is malformed",
            number + 1
        );
    }
}

/// The common words the capitals rows inflect to, and the exception that
/// takes each of them away (`FIV` is `FIV`, never `five`).
const EXCEPTED: &[&str] = &["five", "fives", "hive", "hived", "hiving"];

/// Whether a term is a capitals row of at most five letters: an abbreviation.
fn is_abbreviation(term: &str) -> bool {
    !term.is_empty() && term.len() <= 5 && term.bytes().all(|byte| byte.is_ascii_uppercase())
}

/// The health cue that makes a sentence a health sentence in each language.
fn cue(lang: &str) -> &'static str {
    match lang {
        "af" => "pasiënt",
        "hu" => "beteg",
        "sl" => "bolnik",
        _ => "patient",
    }
}

/// K-OVERMASK-FIVE: every abbreviation of the lexicon masks its own word, in
/// any case.
#[test]
fn an_abbreviation_masks_its_own_word_in_any_case() {
    for entry in DATA.lines().filter_map(parse_line) {
        if entry.cue || entry.except.is_some() || !is_abbreviation(&entry.term) {
            continue;
        }
        let mut chars = entry.term.chars();
        for spelling in [
            entry.term.clone(),
            entry.term.to_lowercase(),
            chars
                .next()
                .map(|first| first.to_string() + chars.as_str())
                .unwrap_or_default(),
        ] {
            let text = format!("{}: {spelling}.", cue(&entry.lang));
            assert!(
                hits(&text).contains(&spelling),
                "{spelling} ({}) left in clear: {text}",
                entry.term
            );
        }
    }
}

/// K-OVERMASK-FIVE: the probe. The inflected forms of the capitals rows, the
/// ones a word list holds: each of them is either excepted by its row or
/// still masked by the lexicon (`hives` is urticaria, and health fails
/// closed).
#[test]
fn a_capitals_row_excepts_the_common_words_it_infects_to() {
    let words: Vec<String> = std::fs::read_to_string("/usr/share/dict/words")
        .map(|text| {
            text.lines()
                .map(|line| line.trim().to_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let mut collisions: HashSet<String> = HashSet::new();
    for entry in DATA.lines().filter_map(parse_line) {
        if entry.cue || entry.except.is_some() || !is_abbreviation(&entry.term) {
            continue;
        }
        let base = fold_str(&entry.term);
        let legacy = Token {
            text: base.clone(),
            stem: false,
            inflection: match entry.lang.as_str() {
                "sl" => Inflection::Slovene,
                "hu" => Inflection::Hungarian,
                "en" => Inflection::English,
                _ => Inflection::Plain,
            },
            excluded: Vec::new(),
        };
        // Every word of the list the row's stem takes: the forms the row
        // inflects to are the words it matches.
        let stem = match entry.lang.as_str() {
            "sl" => slovene_stem(&base).to_string(),
            "hu" => hungarian_stem(&base).to_string(),
            _ => base.clone(),
        };
        for word in words.iter().filter(|w| w.starts_with(&stem) && *w != &base) {
            if legacy.matches(word, true) {
                collisions.insert(word.clone());
            }
        }
    }
    for word in &collisions {
        if hits(word).is_empty() {
            assert!(
                EXCEPTED.contains(&word.as_str()),
                "a new common word is masked: {word}"
            );
        }
    }
}
