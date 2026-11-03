//! What reads as a secret value: its shapes, marks, word reads and the value
//! after a key.

use super::keys::{ATTR_RE, LINKS, MAX_ATTRS, MAX_WORD, MAX_WORDS};

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Class {
    Strong,
    Pin,
    Weak,
    Cookie,
}

pub(super) fn class_of(key: &str) -> Class {
    let key = key.to_lowercase().replace(['\\', '_', '-'], " ");
    if key.starts_with("pin") || key.starts_with("code") && key.ends_with("pin") {
        Class::Pin
    } else if key.contains("cookie") {
        Class::Cookie
    } else if ["token", "tokens", "jeton", "jetons"].contains(&key.as_str()) {
        Class::Weak
    } else {
        Class::Strong
    }
}

/// Signs a password holds; quotes, markup (`~~` included), `=`, `/`, `-` and `_`
/// are left out, so a tag, an attribute or a hyphenated word is no password.
const SIGNS: &str = "!#$%&@^?+|{}";

/// An e-mail address, a URL, a date or a closing tag is not a secret value.
fn is_other_value(value: &str) -> bool {
    let date = value.as_bytes().get(..10).is_some_and(|head| {
        head.iter().enumerate().all(|(at, byte)| match at {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
        })
    });
    date || value.contains("://")
        || value.contains("</")
        || value
            .split_once('@')
            .is_some_and(|(user, host)| !user.is_empty() && host.contains('.'))
}

/// Six or more characters: letters and digits, or a password sign with either.
pub(super) fn strong(value: &str) -> bool {
    let count = value.chars().count();
    let alpha = value.chars().any(char::is_alphabetic);
    let digit = value.chars().any(|ch| ch.is_ascii_digit());
    let sign = value.chars().any(|ch| SIGNS.contains(ch));
    (6..=256).contains(&count)
        && (alpha && digit || sign && (alpha || digit))
        && !is_other_value(value)
}

/// Twelve or more characters of a token alphabet (letters, digits, `_.-+/=`),
/// with letters and digits: a bare `token` is often prose, and filler
/// such as `%41` or `&#x41;` is no token.
fn weak(value: &str) -> bool {
    value.chars().count() >= 12
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "_.-+/=".contains(ch))
        && value.chars().any(char::is_alphabetic)
        && value.chars().any(|ch| ch.is_ascii_digit())
        && !is_other_value(value)
}

pub(super) fn is_value(value: &str, class: Class) -> bool {
    match class {
        Class::Strong => strong(value),
        Class::Pin => {
            (4..=8).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
                || strong(value)
        }
        Class::Weak => weak(value),
        Class::Cookie => match value.split_once('=') {
            Some((name, rest)) if !name.is_empty() => {
                rest.chars().count() >= 16 || strong(rest) || weak(rest)
            }
            _ => weak(value),
        },
    }
}

const BRACKETS: &[char] = &['(', '«', '“', '‘', '[', '<'];
const ENDS: &[char] = &['.', ',', ';', ':', ')', '»', '”', '’', ']', '>'];
/// Quote and emphasis marks: trimmed only in pairs, since a password may start
/// or end with one.
const MARKS: &[char] = &['"', '\'', '`', '*'];

/// The value range of the word `text[start..end]`, its marks trimmed.
pub(super) fn core(text: &str, start: usize, end: usize) -> (usize, usize) {
    let word = &text[start..end];
    let mut start = end - word.trim_start_matches(BRACKETS).len();
    let mut end = start + text[start..end].trim_end_matches(ENDS).len();
    while let Some(mark) = text[start..end]
        .chars()
        .next()
        .filter(|ch| MARKS.contains(ch))
    {
        if end - start < 2 || !text[start..end].ends_with(mark) {
            break;
        }
        start += 1;
        end = start + text[start..end - 1].trim_end_matches(ENDS).len();
    }
    (start, end)
}

/// The end of a cookie value's attributes and further pairs, from `at`.
pub(super) fn attrs_end(text: &str, mut at: usize) -> usize {
    for _ in 0..MAX_ATTRS {
        let Some(found) = ATTR_RE.find(&text[at..]) else {
            break;
        };
        at += found.end();
    }
    at
}

/// The next word after `at` on the line: its range, or `None` at a line end, a
/// text end or a word too long to be a value.
pub(super) fn next_word(text: &str, at: usize) -> Option<(usize, usize)> {
    let rest = bounded(text, at);
    let start = at + rest.len() - rest.trim_start_matches([' ', '\t']).len();
    let rest = bounded(text, start);
    if rest.is_empty() || rest.starts_with(['\n', '\r']) {
        return None;
    }
    let len = match rest.find(char::is_whitespace) {
        Some(len) => len,
        None if start + rest.len() == text.len() => rest.len(),
        None => return None,
    };
    (len <= MAX_WORD).then_some((start, start + len))
}

/// `text[at..]`, cut to `MAX_WORD + 1` bytes on a char boundary, so a read
/// never walks the whole text.
pub(super) fn bounded(text: &str, at: usize) -> &str {
    let mut end = (at + MAX_WORD + 1).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[at..end]
}

/// Whether `word` links a key to the next word: a link word, or a word that ends
/// in `,`, `:`, `=` or `(`, or holds no letter or digit and one of them.
fn links(word: &str) -> bool {
    let bare = word.trim_matches(|ch: char| !ch.is_alphanumeric());
    if bare.is_empty() {
        return word.contains([':', '=', ',', '(', '-', '>', '：']);
    }
    let trimmed = word.trim_end_matches(['*', '_', '`', '"', '\'', ')']);
    trimmed.ends_with([',', ':', '=', '(', '：'])
        || LINKS.contains(&bare.to_lowercase().as_str()) && bare.len() == word.len()
}

/// The value after the key that ends at `key_end`, if one follows a link.
pub(super) fn value_after(text: &str, key_end: usize, class: Class) -> Option<(usize, usize)> {
    let mut at = key_end;
    // The rest of the key's own word: a link glued to it (`pin:`, `key=X`), or a
    // compound (`password-protected`), which links nothing.
    let mut linked = true;
    let glued = bounded(text, at)
        .split(char::is_whitespace)
        .next()
        .unwrap_or("");
    if glued.starts_with(['.', '!', '?']) {
        return None;
    }
    if !glued.is_empty() {
        let mark_len = glued.len()
            - glued
                .trim_start_matches(['*', '_', '`', '"', '\'', ')', ':', '=', ',', '：'])
                .len();
        let marks = &glued[..mark_len];
        if marks.is_empty() || !marks.contains([':', '=', ',', '：']) && mark_len < glued.len() {
            linked = false;
            at += glued.len();
        } else {
            at += mark_len;
            if mark_len < glued.len() {
                let (start, end) = core(text, at, at + glued.len() - mark_len);
                if is_value(&text[start..end], class) {
                    return Some((start, end));
                }
                at += glued.len() - mark_len;
            }
        }
    }
    for _ in 0..MAX_WORDS {
        let (start, end) = next_word(text, at)?;
        let word = &text[start..end];
        let (value_start, value_end) = core(text, start, end);
        let opened = word.starts_with(BRACKETS) || word.starts_with(MARKS);
        if (linked || opened) && is_value(&text[value_start..value_end], class) {
            return Some((value_start, value_end));
        }
        if ["e.g.", "i.e.", "ex."].contains(&word.to_lowercase().as_str()) {
            linked = true;
            at = end;
            continue;
        }
        let ends = word
            .trim_end_matches(['"', '\'', ')', '*', '`'])
            .ends_with(['.', '!', '?']);
        if ends {
            return None;
        }
        linked = links(word);
        at = end;
    }
    None
}
