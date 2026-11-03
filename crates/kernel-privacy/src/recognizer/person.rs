//! The person spans: growing a name over the tokens of a full name.

use crate::contacts::fold::is_default_ignorable;
use crate::span::{EntityKind, Span};

use super::spans::span_is_well_formed;

/// Extend every `PERSON` span over the adjacent capitalised name tokens.
///
/// A detector may flag only part of a multi-token name — the given name alone
/// (`Camille` in `Camille Exemple`), or the family name alone. Masking only
/// that part leaves the rest of the name in clear, so the region grows over the
/// neighbouring capitalised tokens. Joiners (`-`, `'`, `’`) and the zero-width
/// and non-breaking separators are crossed; an address boundary (`@`, `.`,
/// `<`, `>`, `(`, `"`) is not.
pub(super) fn expand_person_spans(text: &str, spans: Vec<Span>) -> Vec<Span> {
    spans
        .into_iter()
        .map(|mut span| {
            if span.kind != EntityKind::Person {
                return span;
            }
            while let Some(end) = next_capitalised_token_end(text, span.end) {
                span.end = end;
            }
            span
        })
        .collect()
}

/// Extend every `PERSON` span over the capitalised words it is joined to by a
/// hyphen, with no space: `Smit` → `Smit-Vosloo` (and chains such as
/// `Halm-Berg-Achterberg`), and `Vosloo` → `Smit-Vosloo` backward.
///
/// A recogniser, the model above all, may flag only one half of a hyphenated
/// surname; the other half would stay in clear. A lower-case word (`Smit-based`),
/// a digit (`COVID-19`) and whitespace stop the growth. Every detector's spans
/// go through this, so each caller gets the same behaviour.
pub(crate) fn extend_hyphenated_persons(text: &str, spans: Vec<Span>) -> Vec<Span> {
    spans
        .into_iter()
        .map(|mut span| {
            if span.kind != EntityKind::Person || !span_is_well_formed(text, &span) {
                return span;
            }
            while let Some(end) = hyphenated_word_after(text, span.end) {
                span.end = end;
            }
            while let Some(start) = hyphenated_word_before(text, span.start) {
                span.start = start;
            }
            span
        })
        .collect()
}

/// The hyphens that join the two parts of a surname: ASCII, U+2010, U+2011.
fn is_hyphen(ch: char) -> bool {
    matches!(ch, '-' | '\u{2010}' | '\u{2011}')
}

/// A letter of a name word, or an apostrophe between two letters (`O'Brien`).
fn is_word_letter(text: &str, at: usize, ch: char) -> bool {
    ch.is_alphabetic()
        || (matches!(ch, '\'' | '\u{2019}')
            && text[..at]
                .chars()
                .next_back()
                .is_some_and(char::is_alphabetic)
            && text[at + ch.len_utf8()..]
                .chars()
                .next()
                .is_some_and(char::is_alphabetic))
}

/// The end of the `-Word` right after `from`, when a hyphen follows directly and
/// the word starts with a capital.
fn hyphenated_word_after(text: &str, from: usize) -> Option<usize> {
    let mut chars = text[from..].chars();
    let hyphen = chars.next().filter(|ch| is_hyphen(*ch))?;
    let start = from + hyphen.len_utf8();
    if !text[start..].chars().next()?.is_uppercase() {
        return None;
    }
    let mut end = start;
    for ch in text[start..].chars() {
        if !is_word_letter(text, end, ch) {
            break;
        }
        end += ch.len_utf8();
    }
    // An address, not a name part: `Smit-Vosloo@x.test`.
    if text[end..].starts_with('@') {
        return None;
    }
    Some(end)
}

/// The start of the `Word-` right before `from`, when a hyphen precedes directly
/// and the word starts with a capital.
fn hyphenated_word_before(text: &str, from: usize) -> Option<usize> {
    let hyphen = text[..from]
        .chars()
        .next_back()
        .filter(|ch| is_hyphen(*ch))?;
    let word_end = from - hyphen.len_utf8();
    let mut start = word_end;
    for (at, ch) in text[..word_end].char_indices().rev() {
        if !is_word_letter(text, at, ch) {
            break;
        }
        start = at;
    }
    if start == word_end || !text[start..].chars().next()?.is_uppercase() {
        return None;
    }
    Some(start)
}

/// The end of the capitalised name token that follows `from` across one
/// separator run, or `None` when the next thing is not one.
fn next_capitalised_token_end(text: &str, from: usize) -> Option<usize> {
    let mut cursor = from;
    let mut crossed = false;
    for ch in text[from..].chars() {
        if is_name_separator(ch) {
            cursor += ch.len_utf8();
            crossed = true;
        } else {
            break;
        }
    }
    if !crossed {
        return None;
    }
    // Never cross into a word that carries an address or a list separator:
    // `Camille@x` and `Exemple,` are boundaries, not name parts.
    let word_end = text[cursor..]
        .find(char::is_whitespace)
        .map(|offset| cursor + offset)
        .unwrap_or(text.len());
    let word = &text[cursor..word_end];
    if word.contains('@') || word.contains(',') {
        return None;
    }
    let mut end = cursor;
    let mut first = true;
    for ch in text[cursor..].chars() {
        if first {
            if !ch.is_uppercase() {
                return None;
            }
            first = false;
            end += ch.len_utf8();
        } else if ch.is_alphabetic() || is_name_joiner(ch) {
            end += ch.len_utf8();
        } else {
            break;
        }
    }
    if end == cursor {
        None
    } else {
        Some(end)
    }
}

/// The horizontal separators a name region may cross: a space, a non-breaking
/// space and the zero-width characters. A line break is not crossed.
fn is_name_separator(ch: char) -> bool {
    matches!(ch, ' ' | '\u{00A0}' | '\u{2007}' | '\u{202F}')
        || is_name_joiner(ch)
        || is_default_ignorable(ch)
}

/// The characters that join the parts of one name.
fn is_name_joiner(ch: char) -> bool {
    matches!(ch, '-' | '\'' | '\u{2019}' | '\u{02BC}' | '`')
}
