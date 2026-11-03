//! The compiled dictionary and its recogniser implementations.

use std::collections::BTreeMap;
use std::sync::Arc;

use aho_corasick::AhoCorasick;

use crate::contacts::fold::{
    fold_homoglyphs, fold_homoglyphs_plain, fold_separators_homoglyphs,
    fold_separators_homoglyphs_plain, Folded,
};
use crate::recognizer::Recognizer;
use crate::recognizers::email::EmailRecognizer;
use crate::span::{EntityKind, Span};

use super::constants::KNOWN_NAMES;
use super::error::NameDictionaryError;
use super::matching::{
    is_capitalised, is_caseless, is_spaced_boundary, preceded_by_title, spaced_stop,
};
use super::rule::PatternRule;
use super::variants::variants_for;

/// The names one caller knows, compiled once for linear matching.
pub struct NameDictionary {
    /// One folded pattern per surface form, matched whole-word.
    names: Option<AhoCorasick>,
    /// The rule for each pattern, indexed by Aho-Corasick pattern id.
    rules: Vec<PatternRule>,
    count: usize,
}

impl NameDictionary {
    /// Compile every surface form of every entry. Blank entries and repeats
    /// are dropped; a form with no letter pair to anchor it is never compiled.
    pub fn new<I, S>(names: I) -> Result<Self, NameDictionaryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut patterns: BTreeMap<String, PatternRule> = BTreeMap::new();
        for name in names {
            for (variant, rule) in variants_for(name.as_ref()) {
                patterns
                    .entry(variant)
                    .and_modify(|current| *current = current.merge(&rule))
                    .or_insert(rule);
            }
        }
        let (patterns, rules): (Vec<String>, Vec<PatternRule>) = patterns.into_iter().unzip();
        Self::compile(patterns, rules)
    }

    /// Compile the folded patterns. An empty pattern is a build error, never a
    /// silently empty dictionary.
    pub(super) fn compile(
        patterns: Vec<String>,
        rules: Vec<PatternRule>,
    ) -> Result<Self, NameDictionaryError> {
        debug_assert_eq!(patterns.len(), rules.len());
        if patterns.iter().any(String::is_empty) {
            return Err(NameDictionaryError::Build);
        }
        if patterns.is_empty() {
            return Ok(Self {
                names: None,
                rules: Vec::new(),
                count: 0,
            });
        }
        let names = AhoCorasick::new(patterns.iter().map(String::as_str))
            .map_err(|_| NameDictionaryError::Build)?;
        Ok(Self {
            names: Some(names),
            rules,
            count: patterns.len(),
        })
    }

    /// How many distinct surface forms are compiled.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the dictionary holds no usable name.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Match on one folded view and append every surviving span.
    fn scan(&self, folded: &Folded, text: &str, emails: &[Span], spans: &mut Vec<Span>) {
        let Some(automaton) = &self.names else {
            return;
        };
        let folded_text = folded.text();
        for found in automaton.find_overlapping_iter(folded_text) {
            let rule = &self.rules[found.pattern().as_usize()];
            let (begin, mut stop) = (found.start(), found.end());
            let mut extended = false;
            if !rule.no_space {
                if !is_spaced_boundary(folded_text[..begin].chars().next_back()) {
                    continue;
                }
                match spaced_stop(folded, text, begin, stop, rule) {
                    Some((end, runs_on)) => (stop, extended) = (end, runs_on),
                    None => continue,
                }
            }
            let (start, end) = folded.source(begin, stop);
            // An inflected form in a cased script is capitalised, all upper case,
            // or after a title: a lower-case tail or stem is some other word.
            let word = &text[start..end];
            if extended
                && !is_caseless(word)
                && !is_capitalised(word)
                && !preceded_by_title(folded_text, begin)
            {
                continue;
            }
            // A comma is a list separator that folding reads as a space: a
            // match that spans one would fuse two names into one region.
            if text[start..end].contains(',') {
                continue;
            }
            // A name may be part of an address (a match wholly inside it), but
            // a match that starts in the display name and ends inside the
            // address must not bridge the two: the address keeps its own
            // region, and the display name its own token.
            if emails.iter().any(|email| {
                start < email.end && end > email.start && (start < email.start || end > email.end)
            }) {
                continue;
            }
            if !rule
                .check_for(word)
                .passes(text, start, end, folded_text, begin)
            {
                continue;
            }
            spans.push(Span::new(EntityKind::Person, start, end, 1.0, KNOWN_NAMES));
        }
    }
}

/// A compiled dictionary shared by several detectors: each gate mounts a
/// handle to the same automaton, never a fresh compile.
impl Recognizer for Arc<NameDictionary> {
    fn kinds(&self) -> &[EntityKind] {
        (**self).kinds()
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        (**self).analyze(text)
    }

    fn name(&self) -> &'static str {
        KNOWN_NAMES
    }
}

impl Recognizer for NameDictionary {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Person]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        if self.names.is_none() {
            return Vec::new();
        }
        let emails = EmailRecognizer::new().analyze(text);
        let mut spans = Vec::new();
        // The separator view finds a name split by a hidden character; the
        // deletion view finds the same name written without it. Each view is
        // read twice, with `Müller` as `mueller` and as `muller`, so a name
        // typed with or without its diacritics matches. Both map back to the
        // original bytes, and the union is masked.
        for (transliterated, plain) in [
            (
                fold_separators_homoglyphs(text),
                fold_separators_homoglyphs_plain(text),
            ),
            (fold_homoglyphs(text), fold_homoglyphs_plain(text)),
        ] {
            self.scan(&transliterated, text, &emails, &mut spans);
            if plain.text() != transliterated.text() {
                self.scan(&plain, text, &emails, &mut spans);
            }
        }
        spans.sort_by_key(|span| (span.start, span.end));
        spans.dedup_by_key(|span| (span.start, span.end));
        spans
    }

    fn name(&self) -> &'static str {
        KNOWN_NAMES
    }
}
