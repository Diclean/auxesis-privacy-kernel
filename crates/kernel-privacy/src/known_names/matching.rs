//! Script-aware boundaries and the text predicates the matcher uses.

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

use crate::contacts::fold::{is_indic_sign, is_no_space_script, Folded};

use super::constants::TITLES;
use super::rule::PatternRule;

/// The script family of `c`, coarse enough to compare a stem and its suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Script {
    Latin,
    Cyrillic,
    Greek,
    Arabic,
    Hebrew,
    Devanagari,
    NoSpace,
    Other,
}

pub(super) fn script_family(c: char) -> Script {
    if is_no_space_script(c) {
        return Script::NoSpace;
    }
    match c {
        '\u{0041}'..='\u{024F}' | '\u{1E00}'..='\u{1EFF}' => Script::Latin,
        '\u{0400}'..='\u{052F}' => Script::Cyrillic,
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Script::Greek,
        '\u{0600}'..='\u{06FF}'
        | '\u{0750}'..='\u{077F}'
        | '\u{08A0}'..='\u{08FF}'
        | '\u{FB50}'..='\u{FDFF}'
        | '\u{FE70}'..='\u{FEFF}' => Script::Arabic,
        '\u{0590}'..='\u{05FF}' | '\u{FB1D}'..='\u{FB4F}' => Script::Hebrew,
        '\u{0900}'..='\u{097F}' => Script::Devanagari,
        _ => Script::Other,
    }
}

/// Whether a spaced-script match may start or end here: a text edge, a
/// non-letter, or a character from a script written without spaces.
pub(super) fn is_spaced_boundary(before: Option<char>) -> bool {
    before.is_none_or(|c| !c.is_alphabetic() || is_no_space_script(c))
}

/// The end of a spaced-script match that starts at `begin` and ends at `stop`,
/// and whether that end runs past the pattern. The match stands as it is when a
/// boundary follows it. Otherwise the word may run on as a tail (one to six
/// letters after the pattern) or as a stem (the whole word, in the stem's
/// letter range), and the run must end at a boundary.
pub(super) fn spaced_stop(
    folded: &Folded,
    text: &str,
    begin: usize,
    stop: usize,
    rule: &PatternRule,
) -> Option<(usize, bool)> {
    let folded_text = folded.text();
    if rule.exact && is_spaced_boundary(folded_text[stop..].chars().next()) {
        return Some((stop, false));
    }
    let first = folded_text[begin..].chars().next()?;
    let script = source_script(folded, text, begin, first);
    let run = run_end(folded, text, begin, script);
    if run <= stop || !is_spaced_boundary(folded_text[run..].chars().next()) {
        return None;
    }
    let tail = rule.tail && (1..=6).contains(&letters(&folded_text[stop..run]));
    let stem = rule
        .stem
        .is_some_and(|range| (range.min..=range.max).contains(&letters(&folded_text[begin..run])));
    (tail || stem).then_some((run, true))
}

/// The end of the run of letters and marks of `script` that starts at `from`.
/// A character from another script, a no-space character or any other symbol
/// ends the run.
fn run_end(folded: &Folded, text: &str, from: usize, script: Script) -> usize {
    let folded_text = folded.text();
    let mut end = from;
    for ch in folded_text[from..].chars() {
        if !is_letter_or_mark(ch)
            || is_no_space_script(ch)
            || source_script(folded, text, end, ch) != script
        {
            break;
        }
        end += ch.len_utf8();
    }
    end
}

/// The script of the source character behind the folded character `ch` at byte
/// `at` of `folded`.
fn source_script(folded: &Folded, text: &str, at: usize, ch: char) -> Script {
    let (start, _) = folded.source(at, at + ch.len_utf8());
    script_family(text[start..].chars().next().unwrap_or(ch))
}

/// Whether the folded word before `begin` is a title.
pub(super) fn preceded_by_title(folded: &str, begin: usize) -> bool {
    let before = folded[..begin].trim_end();
    let word = before
        .rsplit(|ch: char| !ch.is_alphabetic())
        .next()
        .unwrap_or("");
    TITLES.contains(&word)
}

/// Whether `value` is capitalised or all upper case.
pub(super) fn is_capitalised(value: &str) -> bool {
    let letters: Vec<char> = value.chars().filter(|ch| ch.is_alphabetic()).collect();
    match letters.first() {
        Some(first) if first.is_uppercase() => true,
        Some(_) => letters.iter().all(|ch| ch.is_uppercase()),
        None => false,
    }
}

/// The spelling a name is compared by when its diacritics count: NFC and lower
/// case, with the hidden characters and the separators dropped.
pub(super) fn spelling_of(text: &str) -> String {
    cased_of(text)
        .chars()
        .flat_map(char::to_lowercase)
        .collect()
}

/// The spelling of `text` with its case kept: NFC, with the hidden characters
/// and the separators dropped.
pub(super) fn cased_of(text: &str) -> String {
    text.nfc()
        .filter(|c| c.is_alphabetic() || is_combining_mark(*c))
        .collect()
}

/// Whether every letter of `token` is caseless (Hebrew, Arabic, CJK, Thai…).
pub(super) fn is_caseless(token: &str) -> bool {
    let mut any = false;
    for ch in token.chars().filter(|ch| ch.is_alphabetic()) {
        any = true;
        if ch.is_uppercase() || ch.is_lowercase() {
            return false;
        }
    }
    any
}

/// The number of letters in `text`, counting the combining signs of the Indic
/// scripts (see [`is_letter_or_mark`]).
pub(super) fn letters(text: &str) -> usize {
    text.chars().filter(|ch| is_letter_or_mark(*ch)).count()
}

/// Whether `ch` is a letter, or a combining sign of an Indic script (a vowel
/// sign or a virama). A word's length counts its signs: the Tamil `ரவிக்கு`
/// has seven, and its stem `ரவி` has three.
pub(super) fn is_letter_or_mark(ch: char) -> bool {
    ch.is_alphabetic() || is_indic_sign(ch)
}
