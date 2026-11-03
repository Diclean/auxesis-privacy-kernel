//! Deterministic sensitive-terms recogniser (GDPR Art. 9 special categories).
//!
//! Health data is special-category data, so every health term must be masked
//! in full. The recogniser holds a closed, versioned lexicon of unambiguous
//! terms: diagnoses, conditions, treatments and medical-context words in FR,
//! EN, AF, HU, SL and ZH. The vocabulary lives in
//! `data/sensitive-terms-v1.tsv`, compiled into the binary with `include_str!`.
//! Each line is `CATEGORY <TAB> LANG <TAB> TERM`; matching ignores the language.
//!
//! ## Matching
//!
//! * A Latin term is a whole word. The text splits into maximal runs of letters
//!   and digits, and each run is folded to lowercase with its diacritics removed
//!   (NFKD, combining marks dropped), so `Chimiothérapie`, `chimiotherapie` and
//!   `CHIMIOTHÉRAPIE` are one word.
//! * A term fires on the word, and on its plural or feminine form (`s`, `es`,
//!   `e`). A trailing `*` marks a stem: `cukorbeteg*` matches every word that
//!   starts with it.
//! * An exception line (`term|list`) takes words away from a term: a Latin
//!   term lists the words it must not match (`FIV|five,fives`), a Han term the
//!   suffix that must not follow it (`中风|险`).
//! * A multi-word term (`sick leave`, `self-harm`) matches consecutive words
//!   separated only by whitespace, hyphens, apostrophes or invisible characters.
//! * A Han term matches as a substring, because a Chinese sentence has no
//!   spaces between its words.
//!
//! ## Precision
//!
//! Terms fire without a context anchor, so a health value cannot leak past a
//! missing pronoun. Some terms have a common meaning elsewhere, and they
//! over-mask by design: `cancer` as a zodiac sign, `enceinte` as a loudspeaker,
//! `aids` as teaching aids, `rak` as a crab. A name that is also a term is left
//! out of the lexicon.
//!
//! The recogniser never opens a socket, runs a model or logs a value.

use std::collections::{HashMap, HashSet};

use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

use self::conditions::{
    extend_condition_spans, extend_quantified_health, personal_condition_spans,
};
use self::disease::{push_disease_names, push_hu_rak};
use self::eponyms::push_eponym_possessives;
use self::han::{dated, push_han, push_han_disease_names};
use self::lexicon::{lexicons, Hit};
use self::sentence::cued;
use self::text::{is_han, words, HanView};

mod conditions;
mod disease;
mod eponyms;
mod han;
mod inflect;
mod lexicon;
mod sentence;
mod text;

#[cfg(test)]
mod tests;

/// Score of every lexicon hit. A hit is unambiguous, so it sits above every
/// kind floor and keeps its specific label.
pub const SCORE: f32 = 1.0;

/// The name echoed in [`Span::recognizer`].
const NAME: &str = "sensitive_terms";

/// Finds the Art. 9 terms of the lexicon.
#[derive(Clone, Copy, Debug, Default)]
pub struct SensitiveTermsRecognizer;

impl SensitiveTermsRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for SensitiveTermsRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[
            EntityKind::Health,
            EntityKind::Religion,
            EntityKind::SexualOrientation,
            EntityKind::Union,
            EntityKind::Ethnicity,
        ]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let lexicons = lexicons();
        let words = words(text);
        let mut hits: Vec<Hit> = Vec::new();
        let mut cues: Vec<Hit> = Vec::new();
        for index in 0..words.len() {
            lexicons.terms.match_at(text, &words, index, &mut hits);
            lexicons.cues.match_at(text, &words, index, &mut cues);
        }
        lexicons.terms.push_compounds(&words, &mut hits);
        lexicons.terms.push_tagged(&words, &mut hits);
        push_hu_rak(text, &words, &mut hits);
        push_disease_names(text, &words, &mut hits, false);
        push_eponym_possessives(text, &words, &mut hits);
        // Frame-only promotions must never become sentence-wide anchors.
        let mut frames = Vec::new();
        push_disease_names(text, &words, &mut frames, true);
        // Han terms match on the view of the text: traditional characters read
        // as simplified ones, and the matched spans map back to the original.
        if text.chars().any(is_han) {
            let view = HanView::new(text);
            push_han(
                &view,
                &lexicons.terms.han,
                &lexicons.terms.han_except,
                &mut hits,
            );
            push_han_disease_names(&view, text, &mut hits);
            push_han(
                &view,
                &lexicons.cues.han,
                &lexicons.cues.han_except,
                &mut cues,
            );
        }
        extend_quantified_health(text, &words, &mut hits);
        // An ambiguous abbreviation stands only when a strong term or a health
        // cue shares its sentence.
        let mut anchors: HashMap<&'static str, Vec<usize>> = HashMap::new();
        for hit in hits.iter().filter(|hit| !hit.contextual).chain(cues.iter()) {
            anchors.entry(hit.lang).or_default().push(hit.span.start);
        }
        for starts in anchors.values_mut() {
            starts.sort_unstable();
        }
        let mut spans: Vec<Span> = hits
            .into_iter()
            .filter(|hit| {
                if !hit.contextual {
                    return true;
                }
                let own = anchors.get(hit.lang).map_or(&[][..], Vec::as_slice);
                cued(text, hit.span, own) && !dated(text, hit.span)
            })
            .chain(frames)
            .map(|hit| hit.span)
            .collect();
        spans.extend(personal_condition_spans(text, &words));
        extend_condition_spans(text, &words, &mut spans);
        // Two entries can reach the same word (`cancer` and its plural rule):
        // one span per range and kind is enough.
        let mut seen = HashSet::new();
        spans.retain(|span| seen.insert((span.start, span.end, span.kind)));
        spans
    }

    fn name(&self) -> &'static str {
        NAME
    }
}
