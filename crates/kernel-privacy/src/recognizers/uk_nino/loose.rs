//! The loose spellings no main pass reads (ID-LABEL-1), read on the raw text.

use crate::span::{EntityKind, Span};

use super::labels::ni_labelled;
use super::shape::prefix_allowed;
use super::NAME;

/// Two-letter words a lower-case number glued to a word may not start with:
/// `at 10 20 30 cats` is prose (ID-LABEL-1).
const SHORT_WORDS: &[&[u8; 2]] = &[
    b"ah", b"al", b"am", b"an", b"as", b"at", b"ax", b"ay", b"be", b"by", b"ce", b"eh", b"el",
    b"em", b"en", b"er", b"es", b"et", b"ex", b"ha", b"he", b"hm", b"je", b"la", b"le", b"lo",
    b"ma", b"me", b"my", b"ne", b"oh", b"ok", b"on", b"or", b"ow", b"pa", b"sa", b"se", b"so",
    b"ta", b"te", b"we", b"ya", b"ye", b"yo",
];

/// ID-LABEL-1: the spellings no pass above reads, scanned on the original
/// text with each character read as itself:
///
/// * all in lower case with the suffix glued to a word (`pn 48 15 16 cok`),
///   when the boundaries are blanks or zero-width characters and the prefix is
///   no [`SHORT_WORDS`] word: a dotted or dashed one glued is a host or a path,
///   and `Flight BA 12 34 56 dispatched` is prose;
/// * zero-width characters as separators (`PN\u{200b}48…`), which the
///   normalised view drops, so the number read there is compact and glued;
/// * up to three blank, `.` or `-` characters at a boundary (`PN..48..15..16..C`),
///   the same at all four boundaries (`AB-12-34-56 Cat` is a part number), and
///   `/` single (`//` is a path's);
/// * Cyrillic or Greek capitals that look like the Latin ones (`РΝ 48 15 16 С`),
///   only when all three letters are capitals.
///
/// No letter or digit may precede it and no digit follow it. The span ends at
/// the suffix letter. Each try reads at most twenty-one characters: linear.
pub(super) fn loose_ninos(text: &str) -> Vec<Span> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    (0..chars.len())
        .filter_map(|at| {
            let end = loose_at(&chars, at)?;
            let end = chars.get(end).map_or(text.len(), |&(byte, _)| byte);
            Some(Span::new(EntityKind::UkNino, chars[at].0, end, 1.0, NAME))
        })
        .collect()
}

/// The char index one past the suffix letter of a [`loose_ninos`] number that
/// starts at char `at`.
fn loose_at(chars: &[(usize, char)], at: usize) -> Option<usize> {
    let ch = |index: usize| chars.get(index).map(|&(_, c)| c);
    if at > 0 && ch(at - 1).is_some_and(char::is_alphanumeric) {
        return None;
    }
    let first = latin_letter(ch(at)?)?;
    let second = latin_letter(ch(at + 1)?)?;
    if !prefix_allowed(first.0, second.0) {
        return None;
    }
    // ID-LABEL-2: after an explicit NI label, a boundary may also be empty or
    // differ from the others (`NI number: Qq284615b`, `NI no: AB  12 34   56 C`).
    let labelled = ni_labelled(chars, at);
    let (mut index, mut blank, mut mark, mut first_run) = (at + 2, true, None, None);
    for pair in 0..4 {
        // Behind a label, up to eight blanks or tabs (`NI number: Qq\t28 …`).
        let max = if labelled { 8 } else { 3 };
        let run = chars[index.min(chars.len())..]
            .iter()
            .take(max + 1)
            .take_while(|&&(_, c)| loose_separator(c).is_some() || (labelled && c == '\t'))
            .count();
        if (run == 0 && !labelled) || run > max {
            return None;
        }
        let this: Vec<char> = chars[index..index + run].iter().map(|&(_, c)| c).collect();
        if first_run.get_or_insert_with(|| this.clone()) != &this && !labelled {
            return None;
        }
        for &c in &this {
            if loose_separator(c) == Some(false) {
                if mark.is_some_and(|m| m != c) || (c == '/' && run > 1) {
                    return None;
                }
                (blank, mark) = (false, Some(c));
            }
        }
        index += run;
        if pair < 3 {
            if !(ch(index).is_some_and(|c| c.is_ascii_digit())
                && ch(index + 1).is_some_and(|c| c.is_ascii_digit()))
            {
                return None;
            }
            index += 2;
        }
    }
    let suffix = latin_letter(ch(index)?)?;
    let after = ch(index + 1);
    if !matches!(suffix.0, b'A'..=b'D') || after.is_some_and(char::is_numeric) {
        return None;
    }
    let letters = [first, second, suffix];
    let capitals = letters.iter().all(|letter| letter.1);
    let lower = letters.iter().all(|letter| !letter.1);
    if letters.iter().any(|letter| letter.2) && !capitals {
        return None;
    }
    let word = [first.0, second.0].map(|b| b.to_ascii_lowercase());
    if after.is_some_and(char::is_alphabetic)
        && !capitals
        && !labelled
        && (!lower || !blank || SHORT_WORDS.contains(&&word))
    {
        return None;
    }
    Some(index + 1)
}

/// `ch` read as a Latin letter: its capital, whether it is written in capitals,
/// and whether it is a Cyrillic or Greek look-alike.
fn latin_letter(ch: char) -> Option<(u8, bool, bool)> {
    if ch.is_ascii_alphabetic() {
        return Some((
            ch.to_ascii_uppercase() as u8,
            ch.is_ascii_uppercase(),
            false,
        ));
    }
    if !(crate::contacts::fold::is_cyrillic(ch) || crate::contacts::fold::is_greek(ch)) {
        return None;
    }
    let mut lower = ch.to_lowercase();
    let single = lower.next().filter(|_| lower.next().is_none());
    let latin = crate::contacts::fold::homoglyph(ch)
        .or_else(|| single.and_then(crate::contacts::fold::homoglyph))?;
    Some((latin.to_ascii_uppercase() as u8, ch.is_uppercase(), true))
}

/// Whether `ch` may stand at a pair boundary, and whether it is a blank or a
/// zero-width character (`Some(true)`) rather than `.`, `-` or `/`.
fn loose_separator(ch: char) -> Option<bool> {
    match ch {
        ' ' | '\u{a0}' | '\u{2009}' | '\u{202f}' => Some(true),
        '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}' => Some(true),
        '.' | '-' | '/' => Some(false),
        _ => None,
    }
}
