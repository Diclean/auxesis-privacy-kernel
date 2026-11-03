//! Line, token and byte-offset helpers shared by the rules.

use regex::Regex;

use crate::public_terms::fold;
use crate::span::Span;

use super::cues::TITLES;
use super::signals::is_honorific;

/// The bytes of each line, without the trailing newline.
pub(super) fn line_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0usize;
    for (index, ch) in text.char_indices() {
        if ch == '\n' {
            ranges.push((start, index));
            start = index + 1;
        }
    }
    if start < text.len() {
        ranges.push((start, text.len()));
    }
    ranges
}

/// The next line that holds something other than quote markers.
pub(super) fn next_content_line(
    lines: &[(usize, usize)],
    from: usize,
    text: &str,
) -> Option<(usize, usize)> {
    for (start, end) in lines.iter().skip(from) {
        let line = &text[*start..*end];
        if !line.trim().trim_start_matches(['>', ' ', '\t']).is_empty() {
            return Some((*start, *end));
        }
    }
    None
}

/// The next line of a sign-off block that may name the author.
///
/// Like [`next_content_line`], but it also steps over the emoji-only or
/// title-only lines a closing and its name can have between them
/// (`Mit freundlichen Grüßen` / `😊` / `Mila`), up to a bounded count.
pub(super) fn next_signoff_line(
    lines: &[(usize, usize)],
    from: usize,
    text: &str,
) -> Option<(usize, usize)> {
    let mut skipped = 0usize;
    for (start, end) in lines.iter().skip(from) {
        let line = &text[*start..*end];
        let body = line[strip_quote_prefix(line)..].trim();
        if body.is_empty() {
            continue;
        }
        if skipped < 4 && is_signoff_noise(body) {
            skipped += 1;
            continue;
        }
        return Some((*start, *end));
    }
    None
}

/// Whether a non-empty sign-off line is an emoji-only or title-only line rather
/// than the author's name.
fn is_signoff_noise(body: &str) -> bool {
    if !body.chars().any(char::is_alphanumeric) {
        return true;
    }
    let tokens = word_tokens(body);
    !tokens.is_empty()
        && tokens.iter().all(|token| {
            is_honorific(&token.folded) || TITLES.iter().any(|t| fold(t) == token.folded)
        })
}

/// A word token of the decoded text.
pub(super) struct WordToken {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) folded: String,
}

/// Split `text` into Unicode word tokens (a combining mark stays inside its
/// token).
pub(super) fn word_tokens(text: &str) -> Vec<WordToken> {
    let mut tokens = Vec::new();
    let mut current: Option<usize> = None;
    for (index, ch) in text.char_indices() {
        if ch.is_alphanumeric() || unicode_normalization::char::is_combining_mark(ch) {
            current.get_or_insert(index);
        } else if let Some(start) = current.take() {
            tokens.push(token(text, start, index));
        }
    }
    if let Some(start) = current {
        tokens.push(token(text, start, text.len()));
    }
    tokens
}

/// Build one token.
fn token(text: &str, start: usize, end: usize) -> WordToken {
    WordToken {
        start,
        end,
        folded: fold(&text[start..end]),
    }
}

/// Whether a character may join a first name to its surname.
pub(super) fn is_word_separator(ch: char) -> bool {
    matches!(
        ch,
        ' ' | '\t' | '\n' | '\r' | '-' | '_' | '.' | '+' | '\'' | '’'
    )
}

/// Whether `start` opens a line or a sentence (so a lone structural token there
/// is an article or a label, never a surname).
///
/// A bullet marker, a dash or a list number opens a line just like `\n`: the
/// P3 over-masking round found a lone structural token after `•`, `-`, `*`, `>`
/// or `1.` / `a)` being masked as if it were a surname.
pub(super) fn opens_line_or_sentence(text: &str, start: usize) -> bool {
    for ch in text[..start].chars().rev() {
        if ch == '\n' {
            return true;
        }
        if ch.is_whitespace() {
            continue;
        }
        return matches!(ch, '.' | '!' | '?' | ';' | ':' | ')') || is_bullet_marker(ch);
    }
    true
}

/// Whether a character is a bullet or list marker that opens a line.
fn is_bullet_marker(ch: char) -> bool {
    matches!(
        ch,
        '•' | '·' | '◦' | '▪' | '‣' | '⁃' | '–' | '—' | '-' | '*' | '>'
    )
}

/// Whether a raw token is an ALL-CAPS surname (`DUPONT`).
pub(super) fn is_all_caps_surname(raw: &str) -> bool {
    let letters = raw.chars().filter(|ch| ch.is_alphabetic()).count();
    letters >= 2 && !raw.chars().any(char::is_lowercase)
}

/// How many word tokens a person span holds.
pub(super) fn name_token_count(text: &str, span: &Span) -> usize {
    if span.start >= span.end
        || span.end > text.len()
        || !text.is_char_boundary(span.start)
        || !text.is_char_boundary(span.end)
    {
        return 0;
    }
    word_tokens(&text[span.start..span.end]).len()
}

/// Whether the last non-initial word before `start` on the same line is an
/// honorific (`Dr. H. Nel` keeps `Nel`).
pub(super) fn preceded_by_honorific(text: &str, start: usize) -> bool {
    let line_start = text[..start].rfind('\n').map(|at| at + 1).unwrap_or(0);
    let tokens = word_tokens(&text[line_start..start]);
    for token in tokens.iter().rev() {
        if token.folded.chars().count() == 1 {
            continue;
        }
        return is_honorific(&token.folded);
    }
    false
}

/// The byte offset of the first character that is not a quote marker.
pub(super) fn strip_quote_prefix(line: &str) -> usize {
    line.char_indices()
        .find(|(_, ch)| !matches!(ch, ' ' | '\t' | '>'))
        .map(|(index, _)| index)
        .unwrap_or(line.len())
}

/// Trim quote markers, bullets and surrounding space from a line.
pub(super) fn trim_signature_prefix(line: &str) -> &str {
    let offset = line
        .char_indices()
        .find(|(_, ch)| !matches!(ch, ' ' | '\t' | '>' | '-' | '*' | '•'))
        .map(|(index, _)| index)
        .unwrap_or(line.len());
    line[offset..].trim()
}

/// Skip whitespace and the punctuation that separates a greeting from a name.
pub(super) fn skip_separators(value: &str) -> usize {
    value
        .char_indices()
        .find(|(_, ch)| {
            !(ch.is_whitespace()
                || matches!(ch, ',' | ':' | ';' | '.' | '!' | '?' | '-' | '–' | '—'))
        })
        .map(|(index, _)| index)
        .unwrap_or(value.len())
}

/// The first non-prefix character of a line and the trimmed content from there.
pub(super) fn content_after_prefix(line: &str) -> (usize, &str) {
    let offset = line
        .char_indices()
        .find(|(_, ch)| !matches!(ch, ' ' | '\t' | '>' | '-' | '*' | '•'))
        .map(|(index, _)| index)
        .unwrap_or(line.len());
    (offset, line[offset..].trim())
}

/// Whether the byte range `start..start + len` in `text` is a whole word.
pub(super) fn is_token_boundary(text: &str, start: usize, len: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[start + len..].chars().next();
    let free = |ch: Option<char>| ch.is_none_or(|value| !value.is_alphanumeric());
    free(before) && free(after)
}

/// `text` lower-cased one character at a time and, per lowered byte, the byte
/// of `text` its character starts at, plus one entry for the end.
/// `to_lowercase` may change a character's byte length (`İ` -> `i̇`, `ẞ` ->
/// `ß`), so a lowered offset must go through [`original_at`].
pub(super) fn lower_mapped(text: &str) -> (String, Vec<usize>) {
    let mut lowered = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len() + 1);
    for (at, ch) in text.char_indices() {
        for low in ch.to_lowercase() {
            lowered.push(low);
            map.extend(std::iter::repeat_n(at, low.len_utf8()));
        }
    }
    map.push(text.len());
    (lowered, map)
}

/// The byte of the original text a lowered offset `at` stands for, or `None`
/// when `at` falls inside one original character (part of `İ` -> `i̇`).
pub(super) fn original_at(map: &[usize], at: usize) -> Option<usize> {
    let here = *map.get(at)?;
    (at == 0 || map[at - 1] != here).then_some(here)
}

/// The byte range of the first date in `value`, shifted by `base`.
pub(super) fn find_date(value: &str, base: usize) -> Option<(usize, usize)> {
    static YEAR_FIRST: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"\d{4}\s*[./-]\s*\d{1,2}\s*[./-]\s*\d{1,2}").expect("date regex")
    });
    static YEAR_LAST: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"\d{1,2}\s*[./-]\s*\d{1,2}\s*[./-]\s*\d{4}").expect("date regex")
    });
    let found = YEAR_FIRST.find(value).or_else(|| YEAR_LAST.find(value))?;
    Some((base + found.start(), base + found.end()))
}
