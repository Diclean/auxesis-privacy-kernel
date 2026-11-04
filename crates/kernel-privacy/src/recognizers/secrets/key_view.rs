//! The text views a key is read through: folded characters, escaped keys,
//! lower-case AWS ids and the wrapped lines a key joins.

use std::sync::LazyLock;

use regex::Regex;

use crate::contacts::fold::is_default_ignorable;

use super::{SecretRecognizer, MAX_WRAP_BYTES};

/// The keys written with markdown escapes (`AIza…\_…`, `ya29.c.…\-…`).
/// The key alphabet stops at the backslash, so the head before it is too short
/// and the whole key stayed clear. The text is read once more with each
/// backslash before `_` or `-` dropped; a key found there maps back to the text,
/// backslashes included. Only a key that holds a dropped backslash is returned:
/// every other key is the main scan's, read on the same bytes.
pub(super) fn unescaped_keys(text: &str) -> Vec<(usize, usize)> {
    if !text.contains("\\_") && !text.contains("\\-") {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    let mut view = String::with_capacity(text.len());
    // The view offsets where a backslash was dropped, ascending.
    let mut cuts = Vec::new();
    let mut from = 0;
    for (at, _) in text.match_indices('\\') {
        if matches!(bytes.get(at + 1), Some(b'_' | b'-')) {
            view.push_str(&text[from..at]);
            cuts.push(view.len());
            from = at + 1;
        }
    }
    view.push_str(&text[from..]);
    SecretRecognizer::main_spans(&view)
        .into_iter()
        .filter_map(|span| {
            let before_start = cuts.partition_point(|&cut| cut <= span.start);
            let before_end = cuts.partition_point(|&cut| cut < span.end);
            (before_end > before_start)
                .then_some((span.start + before_start, span.end + before_end))
        })
        .collect()
}

/// An AWS access key ID written in lower case (`akia` and sixteen more
/// letters or digits, twenty in all). Lower case reads like prose, so unlike the
/// capital shape no ASCII letter or digit may touch it.
static LOWER_AWS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"akia[0-9a-z]{16}").expect("lower AWS key shape compiles"));

/// The byte ranges of the lower-case AWS access key IDs of `text`.
pub(super) fn lower_aws_keys(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let alnum = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_alphanumeric);
    LOWER_AWS_RE
        .find_iter(text)
        .filter(|key| !(key.start() > 0 && alnum(key.start() - 1)) && !alnum(key.end()))
        .map(|key| (key.start(), key.end()))
        .collect()
}

/// The text as the key shapes read it: zero-width characters are dropped,
/// fullwidth ASCII reads as ASCII, and the dash variants (U+2010 to U+2015, U+2212)
/// read as `-`. Each kept character remembers its original byte span, so a match
/// maps back to the text.
pub(super) struct KeyView {
    pub(super) text: String,
    /// Per kept character: its span in `text`, then in the original.
    cuts: Vec<(usize, usize, usize, usize)>,
}

impl KeyView {
    /// The view of `text`, when a character of it folds or drops. Text without one
    /// (ASCII, or only other non-ASCII such as a masked token's stand-in) is read as
    /// it is: its view would copy the text with one entry per character.
    pub(super) fn for_text(text: &str) -> Option<Self> {
        (!text.is_ascii()
            && text
                .chars()
                .any(|ch| is_default_ignorable(ch) || key_fold(ch) != ch))
        .then(|| Self::new(text))
    }

    fn new(text: &str) -> Self {
        let mut view = KeyView {
            text: String::with_capacity(text.len()),
            cuts: Vec::new(),
        };
        for (start, ch) in text.char_indices() {
            if is_default_ignorable(ch) {
                continue;
            }
            let from = view.text.len();
            view.text.push(key_fold(ch));
            view.cuts
                .push((from, view.text.len(), start, start + ch.len_utf8()));
        }
        view
    }

    /// The original byte span of the view span `start..end`.
    pub(super) fn original(&self, start: usize, end: usize) -> (usize, usize) {
        let first = self
            .cuts
            .binary_search_by_key(&start, |cut| cut.0)
            .unwrap_or(0);
        let last = self
            .cuts
            .binary_search_by_key(&end, |cut| cut.1)
            .unwrap_or(self.cuts.len().saturating_sub(1));
        match (self.cuts.get(first), self.cuts.get(last)) {
            (Some(first), Some(last)) => (first.2, last.3),
            _ => (start, end),
        }
    }
}

/// The ASCII form of a key character: fullwidth ASCII and the dash variants.
fn key_fold(ch: char) -> char {
    match ch {
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(ch as u32 - 0xFEE0).unwrap_or(ch),
        '\u{2010}'..='\u{2015}' | '\u{2212}' => '-',
        _ => ch,
    }
}

/// Whether a character belongs to a key's alphabet.
pub(super) fn is_key_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

/// The key alphabet of a JWT or an SG. key, which also has dots inside it.
pub(super) fn is_dotted_key_char(ch: char) -> bool {
    is_key_char(ch) || ch == '.'
}

/// The length of the line break at `at`, including the OCR form feed and every
/// Unicode line separator the shared normalizer folds.
pub(super) fn break_at(text: &str, at: usize) -> Option<usize> {
    let rest = &text[at..];
    [
        "\r\n", "\n", "\r", "\u{000b}", "\u{000c}", "\u{2028}", "\u{2029}", "\u{85}",
    ]
    .into_iter()
    .find(|line_break| rest.starts_with(line_break))
    .map(str::len)
}

/// The length of the prefix that a continuation line may open with: indentation,
/// quote and `>` markers, and the comment and bullet markers `# `, `// `, `| `
/// and `* `.
fn line_prefix_len(line: &str) -> usize {
    let bytes = line.as_bytes();
    let mut len = 0;
    loop {
        match bytes.get(len) {
            Some(b' ' | b'\t' | b'>' | b'"' | b'\'') => len += 1,
            Some(b'#' | b'|' | b'*') if bytes.get(len + 1) == Some(&b' ') => len += 2,
            Some(b'/')
                if bytes.get(len + 1) == Some(&b'/') && bytes.get(len + 2) == Some(&b' ') =>
            {
                len += 3;
            }
            _ => return len,
        }
    }
}

/// Extend a key over the lines that wrap it. Trailing spaces end a line; the next
/// line opens with an optional prefix (see [`line_prefix_len`]) and then the key
/// alphabet, which joins. A line that does not open with key characters ends the
/// key, so prose after it stays clear; so does a line whose first word is a key
/// name (`NAME=`, `NAME:`). The join is bounded by [`MAX_WRAP_BYTES`].
pub(super) fn join_wrapped(text: &str, from: usize, alphabet: fn(char) -> bool) -> usize {
    let mut limit = (from + MAX_WRAP_BYTES).min(text.len());
    while !text.is_char_boundary(limit) {
        limit -= 1;
    }
    let mut end = from;
    loop {
        let spaces: usize = text[end..]
            .bytes()
            .take_while(|byte| *byte == b' ' || *byte == b'\t')
            .count();
        let at = end + spaces;
        let Some(break_len) = break_at(text, at) else {
            return end;
        };
        let line_start = at + break_len;
        if line_start >= limit {
            return end;
        }
        let run_start = line_start + line_prefix_len(&text[line_start..limit]);
        let run: usize = text[run_start..]
            .char_indices()
            .take_while(|(offset, ch)| run_start + offset < limit && alphabet(*ch))
            .map(|(_, ch)| ch.len_utf8())
            .sum();
        if run == 0 || opens_key_separator(&text[run_start + run..limit]) {
            return end;
        }
        end = run_start + run;
    }
}

/// Whether a line's text, after its key characters, opens with a key separator:
/// `:`, or `=` that is not base64 padding. Such a line is the next key in config
/// text, so a key above it does not wrap into it.
fn opens_key_separator(rest: &str) -> bool {
    rest.starts_with(':') || (rest.starts_with('=') && !rest.starts_with("=="))
}
