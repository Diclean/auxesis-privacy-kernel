//! The separators and the control letters that stand after a digit run.

use super::Body;

/// Whether the byte separates two parts of a printed identifier: a hyphen, a
/// space or a dot. A line break is a space here: the normaliser folds a
/// single break to one.
pub(super) fn es_separator(byte: u8) -> bool {
    matches!(byte, b' ' | b'-' | b'.')
}

/// The end of the run of separators that starts at `at`: the separators a
/// printed identifier may use, one after the other.
fn es_separator_run_end(bytes: &[u8], at: usize) -> usize {
    let mut end = at;
    while end < bytes.len() && es_separator(bytes[end]) {
        end += 1;
    }
    end
}

/// The start of the run of separators that ends at `at`: the separators a
/// printed identifier may use, one after the other.
pub(super) fn es_separator_run_start(bytes: &[u8], at: usize) -> usize {
    let mut start = at;
    while start > 0 && es_separator(bytes[start - 1]) {
        start -= 1;
    }
    start
}

/// Whether the separators `from..to` are spaces only: no hyphen and no dot.
pub(super) fn spaced_only(bytes: &[u8], from: usize, to: usize) -> bool {
    !bytes[from..to]
        .iter()
        .any(|&byte| matches!(byte, b'-' | b'.'))
}

/// The place of the letter after the digits that end at `end`: right after
/// them, or after one separator; a run of separators that holds a line break
/// is one separator.
pub(super) fn letter_after(body: &Body, end: usize) -> Option<usize> {
    let bytes = body.text.as_bytes();
    let byte = *bytes.get(end)?;
    if byte.is_ascii_alphabetic() {
        return Some(end);
    }
    if !es_separator(byte) {
        return None;
    }
    let run_end = es_separator_run_end(bytes, end);
    let at = if run_end > end + 1 {
        // The run holds more than one separator: it is one separator only when
        // it holds a line break.
        if !body.holds_break(end, run_end) {
            return None;
        }
        run_end
    } else {
        end + 1
    };
    bytes.get(at)?.is_ascii_alphabetic().then_some(at)
}
