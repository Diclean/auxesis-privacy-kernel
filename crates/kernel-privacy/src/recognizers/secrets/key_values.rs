//! Key-value and block secrets: separators, quoted values, k8s pairs, XML
//! elements and command-line flags.

use std::cell::Cell;
use std::sync::LazyLock;

use regex::Regex;

use super::key_names::{
    is_blank, is_block_header, is_commented_block_header, is_key_byte, key_before, name_class,
    separator_len, skip_blanks, KeyClass, SecretValue, MAX_BLOCK_BYTES, MAX_QUOTED_BYTES,
    MAX_TERMINATOR_WORD, MAX_VALUE_BYTES, MIN_PASSWORD_LENGTH,
};
use super::key_view::break_at;

/// Line breaks of a text, indexed once. A value finds its line end by binary search,
/// so a long line with many values stays linear.
pub(super) struct Breaks {
    /// Byte offsets of every LF.
    newlines: Vec<usize>,
    /// Byte offsets of every line break: LF, CR, U+2028 and U+85.
    all: Vec<usize>,
    len: usize,
    /// The last line trimmed: its LF (or the text end), and the end of its
    /// content before trailing blanks and CR. Each line is trimmed once, not
    /// once per value on it.
    trimmed: Cell<Option<(usize, usize)>>,
}

impl Breaks {
    /// One pass over the bytes: the byte forms of U+2028 and U+85 are checked only at
    /// their lead byte.
    pub(super) fn new(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut newlines = Vec::new();
        let mut all = Vec::new();
        for (at, &byte) in bytes.iter().enumerate() {
            match byte {
                b'\n' => {
                    newlines.push(at);
                    all.push(at);
                }
                b'\r' => all.push(at),
                0xE2 if bytes[at..].starts_with("\u{2028}".as_bytes()) => all.push(at),
                0xC2 if bytes[at..].starts_with("\u{85}".as_bytes()) => all.push(at),
                _ => {}
            }
        }
        Self {
            newlines,
            all,
            len: text.len(),
            trimmed: Cell::new(None),
        }
    }

    /// The end of the content of the line that ends at `line_stop`, its
    /// trailing blanks and CR taken out.
    fn content_end(&self, text: &str, line_stop: usize) -> usize {
        match self.trimmed.get() {
            Some((stop, end)) if stop == line_stop => end,
            _ => {
                let end = text[..line_stop].trim_end_matches(is_trailing_blank).len();
                self.trimmed.set(Some((line_stop, end)));
                end
            }
        }
    }

    /// The first LF at or after `from`, or the text end.
    fn newline_from(&self, from: usize) -> usize {
        self.newlines
            .get(self.newlines.partition_point(|&at| at < from))
            .copied()
            .unwrap_or(self.len)
    }

    /// The first line break of any kind at or after `from`, or the text end.
    pub(super) fn break_from(&self, from: usize) -> usize {
        self.all
            .get(self.all.partition_point(|&at| at < from))
            .copied()
            .unwrap_or(self.len)
    }

    /// The start of the line that holds `at`.
    fn line_start(&self, at: usize) -> usize {
        match self.newlines.partition_point(|&stop| stop < at) {
            0 => 0,
            index => self.newlines[index - 1] + 1,
        }
    }
}

/// The value after a separator, on its line, with the end of its unbounded remainder
/// (the rest of the line, which decides the minimum length). A quoted value ends at
/// its matching closing quote, even on a later line, within [`MAX_QUOTED_BYTES`]. An
/// unquoted one ends at the first of: the line end, a `&` that starts a query
/// parameter, or a blank that starts another assignment or flag. A value past
/// [`MAX_VALUE_BYTES`] is the whole remainder of its line, masked as one secret. A
/// line with no value, or a block-scalar header, takes the lines indented under the
/// key instead.
fn rest_value(
    text: &str,
    breaks: &Breaks,
    sep: usize,
    after: usize,
) -> Option<(SecretValue, usize)> {
    let bytes = text.as_bytes();
    // Only LF ends a value's line: a lone CR or U+2028 stays inside the value.
    let line_stop = breaks.newline_from(after);
    let start = skip_blanks(bytes, after);
    let rest = &text[start..breaks.content_end(text, line_stop).max(start)];
    if rest.is_empty() || is_block_header(rest) {
        let block = block_value(text, breaks, sep, breaks.break_from(after))?;
        return Some((block, block.end));
    }
    // A header with a comment (`password: | # db`) takes its block too, from
    // the header on, so it hides all the inline reading hid and the block.
    if is_commented_block_header(rest) {
        if let Some(block) = block_value(text, breaks, sep, breaks.break_from(after)) {
            // Long as its block is: the header and comment bytes do not count.
            let value = SecretValue {
                start,
                end: block.end,
                long: block.long,
            };
            return Some((value, block.end));
        }
    }
    if let Some(end) = quoted_end(text, start) {
        let value = SecretValue {
            start,
            end,
            long: false,
        };
        return Some((value, line_stop.max(end)));
    }
    let end = item_end(text, start, unquoted_end(text, start, line_stop));
    let end = if end - start > MAX_VALUE_BYTES {
        start + rest.len()
    } else {
        end
    };
    if end == start {
        return None;
    }
    let value = SecretValue {
        start,
        end,
        long: false,
    };
    Some((value, start + rest.len()))
}

/// The end, after its closing quote, of a quoted value that opens at `open`. A double
/// quote takes a backslash escape; a single quote takes YAML's doubled `''`. The quote
/// may close on a later line, within [`MAX_QUOTED_BYTES`]. `None` when `open` is not
/// a quote, or the quote does not close in that span.
fn quoted_end(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let quote = match bytes.get(open) {
        Some(&byte @ (b'"' | b'\'')) => byte,
        _ => return None,
    };
    let limit = bytes.len().min(open + 1 + MAX_QUOTED_BYTES);
    let mut at = open + 1;
    while at < limit {
        match bytes[at] {
            b'\\' if quote == b'"' => at += 2,
            byte if byte == quote => {
                if quote == b'\'' && at + 1 < limit && bytes[at + 1] == b'\'' {
                    at += 2;
                } else {
                    return Some(at + 1);
                }
            }
            _ => at += 1,
        }
    }
    None
}

/// The raw end of an unquoted value at `start`: the line end, a `&` that starts a
/// query parameter, or the blank that starts another assignment or flag. The search
/// stops one byte past [`MAX_VALUE_BYTES`]: a value with no end inside that span is
/// over the cap, and the caller masks its whole remainder. The first character is
/// part of the value.
fn unquoted_end(text: &str, start: usize, line_stop: usize) -> usize {
    let bytes = text.as_bytes();
    let window = line_stop.min(start + MAX_VALUE_BYTES + 1);
    let mut at = start + text[start..].chars().next().map_or(1, char::len_utf8);
    let mut after_blank = false;
    while at < window {
        match bytes[at] {
            b'&' if is_query_parameter(&text[at + 1..line_stop]) => return at,
            b' ' | b'\t' => {
                if !after_blank
                    && starts_assignment_or_flag(&text[skip_blanks(bytes, at)..line_stop])
                {
                    return at;
                }
                after_blank = true;
            }
            _ => after_blank = false,
        }
        at += 1;
    }
    line_stop
}

/// Whether a byte belongs to a key or query-parameter name.
fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'[' | b']')
}

/// Whether `rest` (the text after a `&`) opens a query parameter: a name of letters,
/// digits and `_ . - [ ]` that starts with a letter or `_`, then `=`.
fn is_query_parameter(rest: &str) -> bool {
    let bytes = rest.as_bytes();
    let name = bytes
        .iter()
        .take(MAX_TERMINATOR_WORD)
        .take_while(|&&byte| is_name_byte(byte))
        .count();
    name > 0
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes.get(name) == Some(&b'=')
}

/// Whether `rest` opens another assignment or flag: `-e` as its own word, `--flag`,
/// or a word of two or more characters (`[A-Za-z_][A-Za-z0-9_.-]*`) followed by `=`
/// or `:`, and then not by another `=`. A `=` at the end of the line does not count,
/// so base64 padding (`abc==`) never ends a value.
fn starts_assignment_or_flag(rest: &str) -> bool {
    if let Some(after) = rest.strip_prefix("-e") {
        if after.is_empty() || after.starts_with(is_blank) {
            return true;
        }
    }
    if let Some(after) = rest.strip_prefix("--") {
        if after.starts_with(|ch: char| ch.is_ascii_alphabetic()) {
            return true;
        }
    }
    let bytes = rest.as_bytes();
    let word = bytes
        .iter()
        .take(MAX_TERMINATOR_WORD)
        .take_while(|&&byte| is_name_byte(byte) && byte != b'[' && byte != b']')
        .count();
    if word < 2 || !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return false;
    }
    match bytes.get(word) {
        Some(b':') => bytes.get(word + 1) != Some(&b'='),
        Some(b'=') => !matches!(bytes.get(word + 1), None | Some(b'=' | b'\r' | b'\n')),
        _ => false,
    }
}

/// The end of an unquoted value: its trailing blanks and CR are not part of it, and
/// one `,` or `;` before them ends a JSON or INI item.
fn item_end(text: &str, start: usize, end: usize) -> usize {
    let trimmed = |end: usize| start + text[start..end].trim_end_matches(is_trailing_blank).len();
    let end = trimmed(end);
    if end > start && matches!(text.as_bytes()[end - 1], b',' | b';') {
        trimmed(end - 1)
    } else {
        end
    }
}

/// Whether a character is trailing noise on a value's line: a blank or a CR.
fn is_trailing_blank(ch: char) -> bool {
    ch == ' ' || ch == '\t' || ch == '\r'
}

/// The block under a key: the lines below the key line that are indented deeper than
/// the key line, blank lines included. The first line that is not deeper ends it.
fn block_value(
    text: &str,
    breaks: &Breaks,
    sep: usize,
    key_line_stop: usize,
) -> Option<SecretValue> {
    let bytes = text.as_bytes();
    let key_line = breaks.line_start(sep);
    let indent = skip_blanks(bytes, key_line) - key_line;
    let mut line = key_line_stop + break_at(text, key_line_stop)?;
    let mut first: Option<usize> = None;
    let mut last = 0;
    while line < bytes.len() {
        let end = breaks.break_from(line);
        let content = skip_blanks(bytes, line);
        if content < end {
            if content - line <= indent {
                break;
            }
            if first.is_none() {
                first = Some(content);
            }
            last = end;
        }
        match break_at(text, end) {
            Some(len) => line = end + len,
            None => break,
        }
    }
    let start = first?;
    Some(SecretValue {
        start,
        end: last,
        long: last - start > MAX_BLOCK_BYTES,
    })
}

/// The key-value secrets: every separator whose key before it is secret-class, with the
/// value after it. A password value needs [`MIN_PASSWORD_LENGTH`] characters in its
/// whole unbounded remainder, so a cut at a terminator never drops a value.
pub(super) fn key_values(text: &str) -> Vec<SecretValue> {
    let breaks = Breaks::new(text);
    let mut values = Vec::new();
    // A value holds the separators inside it: they start no new key.
    let mut resume = 0;
    for (sep, _) in text.char_indices() {
        if sep < resume {
            continue;
        }
        let Some(len) = separator_len(text, sep) else {
            continue;
        };
        // The key is checked before any value is read.
        let Some(class) = key_before(text, sep) else {
            continue;
        };
        let Some((value, remainder)) = rest_value(text, &breaks, sep, sep + len) else {
            continue;
        };
        if class == KeyClass::Password
            && text[value.start..remainder]
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .take(MIN_PASSWORD_LENGTH)
                .count()
                < MIN_PASSWORD_LENGTH
        {
            continue;
        }
        resume = value.end;
        values.push(value);
    }
    values
}

/// Byte spans of the lines of `text`, without their line break. A CRLF is one break,
/// and a lone CR, U+2028 or U+85 is a break too.
pub(super) fn line_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    while let Some(offset) = text[start..].find(['\n', '\r', '\u{2028}', '\u{85}']) {
        let stop = start + offset;
        spans.push((start, stop));
        start = stop + break_at(text, stop).unwrap_or(1);
    }
    spans.push((start, text.len()));
    spans
}

/// A Kubernetes secret env pair: a `- name: <secret-class NAME>` line, then a
/// `value: <x>` line within the next two lines. Only `x` is the secret.
pub(super) fn k8s_values(text: &str) -> Vec<SecretValue> {
    if !text.contains("name:") {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    let lines = line_spans(text);
    let mut values = Vec::new();
    for (index, &(line_start, line_stop)) in lines.iter().enumerate() {
        let mut at = skip_blanks(bytes, line_start);
        if at < line_stop && bytes[at] == b'-' {
            at = skip_blanks(bytes, at + 1);
        }
        if !text[at..line_stop].starts_with("name:") {
            continue;
        }
        let name_start = skip_blanks(bytes, at + "name:".len());
        let name = text[name_start..line_stop]
            .trim_end_matches(is_trailing_blank)
            .trim_matches(|ch: char| ch == '"' || ch == '\'');
        if name.is_empty() || !name.bytes().all(is_key_byte) || name_class(name).is_none() {
            continue;
        }
        for &(next_start, next_stop) in lines.iter().skip(index + 1).take(2) {
            let content = skip_blanks(bytes, next_start);
            if !text[content..next_stop].starts_with("value:") {
                continue;
            }
            let start = skip_blanks(bytes, content + "value:".len());
            let end = start
                + text[start..next_stop]
                    .trim_end_matches(is_trailing_blank)
                    .len();
            if end > start {
                values.push(SecretValue {
                    start,
                    end,
                    long: false,
                });
            }
            break;
        }
    }
    values
}

/// An XML or HTML element whose tag name is secret-class, on one line:
/// `<password>…</password>`. Only its text is the secret.
static XML_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<([A-Za-z][A-Za-z0-9_.:-]*)(?:[ \t][^<>\r\n]*)?>([^<\r\n]+)</[^>\r\n]*>")
        .expect("xml secret shape compiles")
});

pub(super) fn xml_values(text: &str) -> Vec<SecretValue> {
    if !text.contains("</") {
        return Vec::new();
    }
    XML_SECRET_RE
        .captures_iter(text)
        .filter_map(|captures| {
            let name = captures.get(1)?;
            name_class(name.as_str())?;
            let content = captures.get(2)?;
            let raw = content.as_str();
            let trimmed = raw.trim_matches(is_blank);
            if trimmed.is_empty() {
                return None;
            }
            let start = content.start() + (raw.len() - raw.trim_start_matches(is_blank).len());
            Some(SecretValue {
                start,
                end: start + trimmed.len(),
                long: false,
            })
        })
        .collect()
}

/// A command-line secret: `--password value`, `--password=value`, for the flags
/// `password`, `passwd`, `token`, `api-key`, `secret` and `client-secret`. The value
/// is the next token; a value that opens with a quote runs to its matching closing
/// quote, so `"correct horse battery"` is one secret.
static CLI_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)--(password|passwd|token|api-key|secret|client-secret)(?:=|[ \t]+)("(?:\\.|[^"\\\r\n])*"|'[^'\r\n]*'|"[^\r\n]*|'[^\r\n]*|\S+)"#,
    )
    .expect("cli secret shape compiles")
});

pub(super) fn cli_values(text: &str) -> Vec<SecretValue> {
    if !text.contains("--") {
        return Vec::new();
    }
    CLI_SECRET_RE
        .captures_iter(text)
        .filter_map(|captures| {
            let flag = captures.get(1)?.as_str();
            let value = captures.get(2)?;
            let password =
                flag.eq_ignore_ascii_case("password") || flag.eq_ignore_ascii_case("passwd");
            if password
                && value
                    .as_str()
                    .chars()
                    .filter(|ch| !ch.is_whitespace())
                    .count()
                    < MIN_PASSWORD_LENGTH
            {
                return None;
            }
            Some(SecretValue {
                start: value.start(),
                end: value.end(),
                long: false,
            })
        })
        .collect()
}
