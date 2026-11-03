//! The contact recogniser: name variants, identifier keys and span resolution.

use std::cmp::Reverse;
use std::collections::HashMap;

use aho_corasick::{AhoCorasick, BuildError};

use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

use super::fold::{fold, lower_nfkc, plain_address, Folded};
use super::identifiers::{self, insert_key, Target};
use super::variants::{variants_for, Check};
use super::{
    header, ContactIndex, Key, CONTACT_RECOGNIZER, CONTACT_SCORE, WINDOW_BYTES, WINDOW_OVERLAP,
};

/// Matches every variant of every known person, and every e-mail address,
/// phone number and IBAN of a known person.
///
/// Built once from a [`ContactIndex`] (see [`ContactIndex::recognizer`]) and
/// mounted with `RegistryBuilder::with_recognizer`. It never reports a span that
/// is not a whole-word or whole-identifier match in the original text.
pub struct ContactRecognizer {
    /// Folded name variants, one automaton pattern each.
    names: Option<AhoCorasick>,
    /// The people that share each name pattern, by how the match must read.
    name_groups: Vec<Vec<(Check, Target)>>,
    /// E-mail keys: `local@domain` with the local part up to a `+` tag.
    emails: HashMap<Key, Target>,
    /// Phone keys: international digits, and the national forms of a number.
    phones: HashMap<Key, Target>,
    /// IBAN keys: compact, upper-case.
    ibans: HashMap<Key, Target>,
}

impl ContactRecognizer {
    /// Compile every variant and identifier key of every person in `index`.
    pub fn new(index: &ContactIndex) -> Result<Self, BuildError> {
        let mut names: HashMap<Key, Vec<(Check, Target)>> = HashMap::new();
        let mut emails: HashMap<Key, Target> = HashMap::new();
        let mut phones: HashMap<Key, Target> = HashMap::new();
        let mut ibans: HashMap<Key, Target> = HashMap::new();
        for person in index.people() {
            for variant in variants_for(person, index.mask_first_names) {
                let groups = names.entry(Key(variant.text)).or_default();
                match groups.iter_mut().find(|(check, _)| *check == variant.check) {
                    Some((_, target)) => target.ambiguous = true,
                    None => groups.push((
                        variant.check,
                        Target {
                            person: person.id,
                            ambiguous: false,
                        },
                    )),
                }
            }
            for email in &person.emails {
                if let Some(key) = identifiers::email_key(email) {
                    insert_key(&mut emails, key, person.id);
                }
            }
            for phone in &person.phones {
                for key in identifiers::phone_keys(phone) {
                    insert_key(&mut phones, key, person.id);
                }
            }
            for iban in &person.ibans {
                insert_key(&mut ibans, iban.clone(), person.id);
            }
        }
        let (name_patterns, name_groups): (Vec<Key>, Vec<Vec<(Check, Target)>>) =
            names.into_iter().unzip();
        Ok(Self {
            names: automaton(&name_patterns)?,
            name_groups,
            emails,
            phones,
            ibans,
        })
    }

    /// The number of compiled patterns: name variants, e-mail, phone and IBAN
    /// keys. For diagnostics, never for logs of values.
    pub fn pattern_count(&self) -> usize {
        self.name_groups.len() + self.emails.len() + self.phones.len() + self.ibans.len()
    }

    /// How many compiled patterns name more than one person. Such a match masks
    /// under the oldest of them.
    pub fn ambiguous_patterns(&self) -> usize {
        let names = self
            .name_groups
            .iter()
            .flatten()
            .filter(|(_, target)| target.ambiguous)
            .count();
        let emails = self
            .emails
            .values()
            .filter(|target| target.ambiguous)
            .count();
        let phones = self
            .phones
            .values()
            .filter(|target| target.ambiguous)
            .count();
        let ibans = self
            .ibans
            .values()
            .filter(|target| target.ambiguous)
            .count();
        names + emails + phones + ibans
    }

    /// Name matches in `text`: whole words of a folded variant.
    fn names_in(&self, text: &str, spans: &mut Vec<Span>) {
        let Some(automaton) = &self.names else {
            return;
        };
        let folded = fold(text);
        let bytes = folded.text().as_bytes();
        for found in automaton.find_overlapping_iter(folded.text()) {
            let (begin, stop) = (found.start(), found.end());
            // The folded text separates words with single spaces, so a match
            // is a whole word when it sits between spaces or the text edges.
            if (begin > 0 && bytes[begin - 1] != b' ')
                || (stop < bytes.len() && bytes[stop] != b' ')
            {
                continue;
            }
            let (start, end) = folded.source(begin, stop);
            let groups = &self.name_groups[found.pattern().as_usize()];
            if let Some(target) = pick(groups, text, start, end) {
                spans.push(identifier_span(EntityKind::Person, start, end, target));
            }
        }
    }

    /// Address matches in `composed`, the composed, lower-cased text of one
    /// window: any case, composition, percent-encoding and obfuscated spelling.
    fn emails_in(&self, composed: &Folded, spans: &mut Vec<Span>) {
        if self.emails.is_empty() {
            return;
        }
        // The plain text keeps its source map, so its spans are original spans.
        let plain = plain_address(composed);
        for (start, end, target) in identifiers::email_hits(plain.text(), &self.emails) {
            let (start, end) = plain.source(start, end);
            spans.push(identifier_span(EntityKind::Email, start, end, target));
        }
    }

    /// Every match in one window of text, in any order.
    fn scan(&self, text: &str, spans: &mut Vec<Span>) {
        self.names_in(text, spans);
        let composed = lower_nfkc(text);
        self.emails_in(&composed, spans);
        for (start, end, target) in identifiers::phone_hits(composed.text(), &self.phones) {
            let (start, end) = composed.source(start, end);
            spans.push(identifier_span(EntityKind::Phone, start, end, target));
        }
        for (start, end, target) in identifiers::iban_hits(composed.text(), &self.ibans) {
            let (start, end) = composed.source(start, end);
            spans.push(identifier_span(EntityKind::Iban, start, end, target));
        }
    }
}

impl Recognizer for ContactRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Iban,
        ]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for (offset, window) in windows(text) {
            let mut found = Vec::new();
            self.scan(window, &mut found);
            spans.extend(found.into_iter().map(|mut span| {
                span.start += offset;
                span.end += offset;
                span
            }));
        }
        resolve_overlaps(text, spans)
    }

    fn name(&self) -> &'static str {
        CONTACT_RECOGNIZER
    }

    /// The index is an explicit input: the default registry does not mount it.
    fn enabled_by_default(&self) -> bool {
        false
    }
}

/// The pieces of `text` that one scan reads: the whole text when it is short,
/// else windows of [`WINDOW_BYTES`] that overlap by [`WINDOW_OVERLAP`] bytes.
/// Each window starts at the byte offset returned with it. Cuts fall after a
/// line break where one is near, and after a space otherwise, so no word is cut.
fn windows(text: &str) -> Vec<(usize, &str)> {
    if text.len() <= WINDOW_BYTES {
        return vec![(0, text)];
    }
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        let limit = char_floor(text, (start + WINDOW_BYTES).min(text.len()));
        let end = if limit == text.len() {
            limit
        } else {
            break_after(text, start + WINDOW_BYTES / 2, limit).unwrap_or(limit)
        };
        out.push((start, &text[start..end]));
        if end == text.len() {
            return out;
        }
        // The next window starts at the first break inside the overlap, so a name
        // that the cut split is whole in it.
        let overlap_from = char_floor(text, end - WINDOW_OVERLAP);
        start = first_break(text, overlap_from, end).unwrap_or(overlap_from);
    }
}

/// The largest character boundary of `text` that is at most `at`.
fn char_floor(text: &str, mut at: usize) -> usize {
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// The byte after the last line break, or else the last whitespace, in
/// `text[from..to]`. A cut there splits no word: the byte before it is ASCII.
fn break_after(text: &str, from: usize, to: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let line = (from..to).rev().find(|&at| bytes[at] == b'\n');
    line.or_else(|| (from..to).rev().find(|&at| bytes[at].is_ascii_whitespace()))
        .map(|at| at + 1)
}

/// The byte after the first whitespace in `text[from..to]`, when there is one.
fn first_break(text: &str, from: usize, to: usize) -> Option<usize> {
    text.as_bytes()[from..to]
        .iter()
        .position(u8::is_ascii_whitespace)
        .map(|at| from + at + 1)
}

/// Resolves the overlaps of the spans of one text into one match per stretch.
///
/// A span that lies inside a longer one is dropped, so that a surname inside a
/// full name, an address inside its tagged form, or a number inside its
/// international form is one match, under the outer person. Where two people's
/// names partly overlap ("Marie Dupont, Jean Dupont" reads "Dupont, Jean" too),
/// the earlier span keeps the overlap and the later one starts at its first
/// word after it, so every word is masked under one person. Spans of the same
/// person, and identifiers, may overlap. The result is sorted by start.
fn resolve_overlaps(text: &str, spans: Vec<Span>) -> Vec<Span> {
    let mut trimmed: Vec<Span> = Vec::with_capacity(spans.len());
    for mut span in prune_contained(spans) {
        if let Some(earlier) = trimmed.last() {
            let crosses = span.start < earlier.end
                && span.kind == EntityKind::Person
                && earlier.kind == EntityKind::Person
                && span.person_id != earlier.person_id;
            if crosses {
                span.start = first_word(text, earlier.end, span.end);
                if span.start >= span.end {
                    continue;
                }
            }
        }
        trimmed.push(span);
    }
    prune_contained(trimmed)
}

/// Drops every span that lies inside a longer one. The input is sorted by start
/// and the output is too.
fn prune_contained(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by_key(|span| (span.start, Reverse(span.end)));
    let mut kept: Vec<Span> = Vec::with_capacity(spans.len());
    let mut reach = 0;
    for span in spans {
        // Sorted by start, so the span that reaches furthest so far starts first:
        // a span that ends within it lies inside it.
        if !kept.is_empty() && span.end <= reach {
            continue;
        }
        reach = reach.max(span.end);
        kept.push(span);
    }
    kept
}

/// The byte of the first letter or digit in `text[from..to]`, or `to` when there
/// is none. Both bounds are character boundaries.
fn first_word(text: &str, from: usize, to: usize) -> usize {
    text[from..to]
        .char_indices()
        .find(|(_, c)| c.is_alphanumeric())
        .map_or(to, |(at, _)| from + at)
}

/// The span of one identifier hit, carrying its person.
fn identifier_span(kind: EntityKind, start: usize, end: usize, target: Target) -> Span {
    Span::new(kind, start, end, CONTACT_SCORE, CONTACT_RECOGNIZER).with_person(target.person)
}

/// The Aho-Corasick automaton of `patterns`, or `None` when there are none.
fn automaton(patterns: &[Key]) -> Result<Option<AhoCorasick>, BuildError> {
    if patterns.is_empty() {
        return Ok(None);
    }
    AhoCorasick::new(patterns.iter().map(Key::as_str)).map(Some)
}

/// The target of the first group whose check the matched text passes: a plain
/// match first, then an initial, then an initialism, then a titled surname, and
/// last a function word in name context.
fn pick(groups: &[(Check, Target)], text: &str, start: usize, end: usize) -> Option<Target> {
    [
        Check::Any,
        Check::FirstUpper,
        Check::AllUpper,
        Check::Titled,
        Check::Context,
    ]
    .into_iter()
    .find_map(|check| {
        groups
            .iter()
            .find(|(group, _)| *group == check && check_passes(text, start, end, check))
            .map(|(_, target)| *target)
    })
}

/// Whether the match `text[start..end]` satisfies `check`: its letters, its last
/// word, or the text around it.
fn check_passes(text: &str, start: usize, end: usize, check: Check) -> bool {
    let mut letters = text[start..end].chars().filter(|c| c.is_alphabetic());
    match check {
        Check::Any => true,
        Check::FirstUpper => letters.next().is_some_and(|c| !c.is_lowercase()),
        Check::AllUpper => letters.all(|c| !c.is_lowercase()),
        Check::Titled => {
            let surname = text[start..end]
                .rsplit(|c: char| !c.is_alphabetic())
                .next()
                .unwrap_or_default();
            surname.chars().next().is_some_and(|c| !c.is_lowercase())
        }
        Check::Context => in_name_context(text, start, end),
    }
}

/// Whether the match `text[start..end]` is name context: the only words on its
/// line (a signature, a quoted line), or the value of a mail header.
fn in_name_context(text: &str, start: usize, end: usize) -> bool {
    let line_start = text[..start].rfind('\n').map_or(0, |at| at + 1);
    let line_end = text[end..].find('\n').map_or(text.len(), |at| end + at);
    let before = &text[line_start..start];
    let after = &text[end..line_end];
    let alone = before.chars().chain(after.chars()).all(is_signature_filler);
    alone || header::is_header_value(before)
}

/// Whitespace, and the punctuation of a signature or a quote marker.
fn is_signature_filler(c: char) -> bool {
    c.is_whitespace() || "-–—|·•*_~>.,;".contains(c)
}
