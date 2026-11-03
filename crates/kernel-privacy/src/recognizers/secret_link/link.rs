//! Separators, link endings and weak-key checks for the secret-link scanner.

use super::lex::{fold, is_mark, is_sentinel};
use super::{Line, Shape, HEADS, LINKS, WINDOW};

pub(super) fn sep_len(text: &str) -> Option<usize> {
    [":=", "=>", "->", ":", "=", "："]
        .iter()
        .find(|sep| text.starts_with(**sep))
        .map(|sep| sep.len())
}

/// After a separator, emphasis marks glued to it are skipped.
fn glued(text: &str, at: usize) -> usize {
    text.len() - text[at..].trim_start_matches(['*', '_', '`', '~']).len()
}

/// The end of the link after a key that ends at `key_end`, on the key's line.
pub(super) fn link(text: &str, key_end: usize, line_end: usize) -> Option<usize> {
    let mut window = line_end;
    let mut size = 0;
    for (at, ch) in text[key_end..line_end].char_indices() {
        size += if is_sentinel(ch) { 1 } else { ch.len_utf8() };
        if size > WINDOW {
            window = key_end + at;
            break;
        }
    }
    let line = &text[..window];
    let mut at = key_end;
    for _ in 0..4 {
        match line[at..].chars().next() {
            Some(ch) if is_mark(ch) => at += ch.len_utf8(),
            _ => break,
        }
    }
    if let Some(len) = sep_len(&line[at..]) {
        return Some(glued(text, at + len));
    }
    for words in 1..=9 {
        at = window - line[at..].trim_start().len();
        let end = line[at..]
            .find(char::is_whitespace)
            .map_or(window, |len| at + len);
        if at == window
            || end == window && text[window..line_end].starts_with(|ch: char| !ch.is_whitespace())
        {
            return None;
        }
        let word = &line[at..end];
        if [":", "=", ":=", "->", "=>", "："].contains(&word) || word.ends_with([':', '=', '：'])
        {
            return Some(glued(text, end));
        }
        if word.starts_with('是') {
            return Some(at + '是'.len_utf8());
        }
        let mut folded = String::new();
        word.chars().for_each(|ch| fold(ch, &mut folded));
        let folded = folded.trim_matches(|ch: char| is_mark(ch) || ch == ' ');
        if LINKS.contains(&folded) {
            return Some(end);
        }
        if words == 1 && !HEADS.contains(&folded) || word.contains(['.', ',', ';', '!', '?']) {
            return None;
        }
        at = end;
    }
    None
}

/// A weak key counts only next to a mark, a cell pipe, or as an Entry's key.
pub(super) fn weak_counts(text: &str, line: &Line, start: usize, end: usize) -> bool {
    let entry_key = matches!(line.shape, Shape::Entry(.., key) if key.0 <= start && end <= key.1);
    let before = text[line.start..start].trim_end_matches([' ', '\t']);
    let after = text[end..line.end]
        .trim_start_matches(is_mark)
        .trim_start_matches([' ', '\t']);
    entry_key
        || text[..start].chars().next_back().is_some_and(is_mark)
        || text[end..].chars().next().is_some_and(is_mark)
        || before.ends_with('|')
        || after.starts_with('|')
}
