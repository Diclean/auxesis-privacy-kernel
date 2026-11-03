//! A label on its own line, and a passphrase key on the line of its value.

use std::sync::LazyLock;

use regex::Regex;

use super::scan::trimmed;

/// Words of a passphrase on the line after its label.
const MAX_PHRASE_WORDS: usize = 8;
/// Words of any value on the line after its label, however long.
const MAX_LINE_WORDS: usize = 16;

/// A label alone on its line (a bullet or a number before it allowed), then
/// the line that holds its value.
static LABEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?im)^[ \t]*(?:(?:[-*•‣◦·]|[0-9]{1,3}[.)])[ \t]+)?(passphrase|password|pin|api[ _-]?key|secret|mot de passe|",
        r"phrase secr[èe]\x{300}?te)[ \t]*:?[ \t]*\r?\n([^\r\n]*)"
    ))
    .expect("label lines compile")
});

/// A passphrase key, then its words on the same line: in brackets or quotes, or
/// to the line end (a colon optional) when they read as no sentence.
static PHRASE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:passphrase|pass phrase|phrase secr[èe]\x{300}?te)\b[ \t]*(?:",
        r#"[(“"«]([^()“”"«»\r\n]+)[)”"»]|:?[ \t]*([^\r\n]+))"#
    ))
    .expect("phrase shapes compile")
});

/// The next line after an explicit secret label is its value, sentence, colon
/// or not, up to [`MAX_LINE_WORDS`] words of any length.
pub(super) fn labels(text: &str, spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(found) = LABEL_RE.captures_at(text, from) {
        let Some(line) = found.get(2) else {
            break;
        };
        // The value line may be a label itself: read it again as one.
        from = line.start();
        let (start, end) = trimmed(text, line.start(), line.end());
        let value = &text[start..end];
        if !value.is_empty() && value.split_whitespace().count() <= MAX_LINE_WORDS {
            spans.push((start, end));
        }
    }
}

/// `headers` are the table header lines, whose cells are names, not phrases.
pub(super) fn phrases(text: &str, headers: &[(usize, usize)], spans: &mut Vec<(usize, usize)>) {
    for found in PHRASE_RE.captures_iter(text) {
        let key = found.get(0).map_or(0, |m| m.start());
        let at = headers.partition_point(|&(_, end)| end < key);
        if headers.get(at).is_some_and(|&(start, _)| start <= key) {
            continue;
        }
        let (inner, words) = match (found.get(1), found.get(2)) {
            (Some(inner), _) => (inner, true),
            (None, Some(rest)) => {
                let last = rest.as_str().trim_end();
                let prose = if text[key..rest.start()].contains(':') {
                    last.ends_with('.')
                } else {
                    last.ends_with(['.', '!', '?'])
                };
                (rest, !prose)
            }
            _ => continue,
        };
        let (start, end) = trimmed(text, inner.start(), inner.end());
        let count = text[start..end].split_whitespace().count();
        if words && (1..=MAX_PHRASE_WORDS).contains(&count) {
            spans.push((start, end));
        }
    }
}
