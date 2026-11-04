//! Shared normalisation layer for scanning.
//!
//! The deterministic recognisers scan a *normalised* view of the input so that
//! a value written with Unicode digits, exotic spaces, dashes or OCR noise is
//! still found, while every span is reported on the original byte offsets.
//! The layer:
//!
//! * maps every Unicode decimal digit (`Nd`) to its ASCII digit, so fullwidth
//!   and Arabic-Indic numbers count as digits;
//! * folds Unicode spaces (NBSP, U+202F, U+2009, …) to ASCII space and the
//!   dash range U+2010–U+2015 plus U+2212 to ASCII `-`;
//! * folds the whole fullwidth ASCII block (letters, digits, punctuation and
//!   the commercial `＠`) to its ASCII form, so `ａｐｐ １０.０.０.５` scans as
//!   `app 10.0.0.5` and `１９２．１６８．０．１` scans as `192.168.0.1`;
//! * folds the ideographic full stop `。` to `.` when it sits between two
//!   digits, so a CJK sentence-ending mark never turns a number into a date;
//! * strips zero-width characters (ZWSP/ZWNJ/ZWJ/WORD JOINER/BOM/soft hyphen);
//! * folds a run of separators that holds a line break or tab (`\n`, `\r\n`,
//!   `\r`, `\t`, with or without spaces around it) to one ASCII space, so an
//!   IBAN or phone number wrapped across lines still scans as one value. A run
//!   folds only within its caps (at most two line breaks and eight separator
//!   characters in all); a longer run becomes a hard boundary that no
//!   identifier crosses, so masking can never swallow a long blank region. The
//!   run's original bytes stay inside the span's offsets. A run that holds a
//!   zero-width character, even without a line break, is capped the same way;
//! * removes a quoted-printable soft break (an `=`, optional blanks, then `\r\n`,
//!   `\r` or `\n`) before the folds, so the two sides join with nothing between
//!   them and a value a mail client wrapped still scans as one value;
//! * optionally folds single OCR confusables (`O`/`o` → `0`, `l`/`I` → `1`)
//!   that sit between or immediately beside digits, so a whole letter word is
//!   never rewritten.

use std::sync::Arc;

mod charset;
mod digits;
mod fold;
mod view;

pub(crate) use charset::{holds_line_break, is_unicode_space};
pub(crate) use digits::unicode_digit_value;
pub(crate) use view::SharedViews;

/// The most line breaks a separator run may hold and still fold to one space.
const MAX_FOLDED_BREAKS: usize = 2;

/// The most separator characters a run may hold and still fold to one space.
const MAX_FOLDED_RUN: usize = 8;

/// What a run too long to fold becomes in the normalised text. A NUL is no
/// digit, letter, space or punctuation any recogniser accepts, so no
/// identifier can cross it.
const RUN_BOUNDARY: char = '\u{0}';

/// A scanned view of a text plus a map from normalised byte offsets back to the
/// original byte offsets. Cloning shares the view.
#[derive(Clone)]
pub struct NormalizedText {
    text: Arc<String>,
    /// Byte offset of each normalised char; empty when offsets are identity.
    char_starts: Arc<[usize]>,
    /// Original `(start, end)` bounds of each normalised char; empty when identity.
    orig_bounds: Arc<[(usize, usize)]>,
    /// `text` is the input unchanged and every byte maps to itself, so
    /// [`NormalizedText::to_original`] is the identity and no map is needed.
    identity: bool,
    /// All normalised chars are one byte, so a byte offset is also a char
    /// index and `char_starts` is empty.
    compact: bool,
}

/// Maximal runs of ASCII digits plus the separators a printed number may use.
///
/// A separator is kept only when the next char is a digit, so trailing
/// punctuation stays outside the span.
pub fn numeric_runs(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut runs = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        let mut cursor = index;
        let mut last_digit_end = index;
        while cursor < bytes.len() {
            let byte = bytes[cursor];
            if byte.is_ascii_digit() {
                last_digit_end = cursor + 1;
                cursor += 1;
            } else if matches!(byte, b' ' | b'-' | b'.' | b'/')
                && cursor + 1 < bytes.len()
                && bytes[cursor + 1].is_ascii_digit()
            {
                cursor += 1;
            } else {
                break;
            }
        }
        runs.push((start, last_digit_end));
        index = cursor.max(index + 1);
    }
    runs
}

/// Consume up to `max_alnum` ASCII alphanumerics starting at `start`, allowing
/// a single separator (` `, `-`, `.`, `/`) between them. Returns the end offset
/// (one past the last consumed alphanumeric).
pub fn consume_alnum(text: &str, start: usize, max_alnum: usize) -> usize {
    let bytes = text.as_bytes();
    let mut cursor = start;
    let mut consumed = 0usize;
    let mut previous_separator = false;
    while cursor < bytes.len() && consumed < max_alnum {
        let byte = bytes[cursor];
        if byte.is_ascii_alphanumeric() {
            consumed += 1;
            previous_separator = false;
            cursor += 1;
        } else if matches!(byte, b' ' | b'-' | b'.' | b'/') && !previous_separator {
            let next_is_alnum =
                cursor + 1 < bytes.len() && bytes[cursor + 1].is_ascii_alphanumeric();
            if !next_is_alnum {
                break;
            }
            previous_separator = true;
            cursor += 1;
        } else {
            break;
        }
    }
    cursor
}

/// The ASCII digits of a raw run, discarding separators.
pub fn ascii_digits(raw: &str) -> String {
    raw.chars().filter(|ch| ch.is_ascii_digit()).collect()
}

#[cfg(test)]
mod tests;
