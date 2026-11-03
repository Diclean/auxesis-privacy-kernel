//! The generic scans the EU rules share: digit runs, shaped runs, cues and
//! opaque tokens.

use crate::normalize::ascii_digits;

use super::body::unwrapped;
use super::{Body, Candidate, Check, Cue, Shape, IT_LENGTH};

/// How far back a label is looked for, in characters.
const CUE_WINDOW: usize = 40;

/// The shortest opaque token a candidate can be part of: a hash, a UUID or a
/// Base64 blob. Masking a part of one would corrupt it.
const OPAQUE_TOKEN_MIN: usize = 20;

/// Whether the candidate sits in an opaque token: an alphanumeric run of
/// [`OPAQUE_TOKEN_MIN`] characters or more around it.
///
/// Only the alphanumerics count, on every side: the punctuation of a printed
/// number is not part of the token, so a value with separators that stands in
/// prose is not a fragment of a hash.
///
/// The run is read at most [`OPAQUE_TOKEN_MIN`] bytes on each side, so the
/// answer is exact and the scan stays linear.
pub(super) fn in_opaque_token(text: &str, candidate: &Candidate) -> bool {
    let length = candidate.end - candidate.start;
    if length >= IT_LENGTH {
        return false;
    }
    let bytes = text.as_bytes();
    let left = alnum_run(&mut bytes[..candidate.start].iter().rev().copied());
    let right = alnum_run(&mut bytes[candidate.end..].iter().copied());
    let inner = bytes[candidate.start..candidate.end]
        .iter()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .count();
    left + inner + right >= OPAQUE_TOKEN_MIN
}

/// The alphanumeric bytes the iterator yields, at most [`OPAQUE_TOKEN_MIN`].
fn alnum_run(bytes: &mut impl Iterator<Item = u8>) -> usize {
    bytes
        .by_ref()
        .take(OPAQUE_TOKEN_MIN)
        .take_while(|byte| byte.is_ascii_alphanumeric())
        .count()
}

/// Whether a label stands within [`CUE_WINDOW`] characters before `start`: the
/// words of the window must hold the words of one cue, in order. The window is
/// read as words, so `Steuer-ID` and `steuer id` are one label.
pub(super) fn has_cue(text: &str, start: usize, cues: &[Cue]) -> bool {
    let from = text[..start]
        .char_indices()
        .rev()
        .nth(CUE_WINDOW)
        .map_or(0, |(at, _)| at);
    let window = text[from..start].to_lowercase();
    let words: Vec<&str> = window
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    cues.iter()
        .any(|cue| cue.len() <= words.len() && words.windows(cue.len()).any(|pair| pair == *cue))
}

/// Every maximal digit run of `text` whose digits number one of `lens`, with
/// the verdict of `check`. The run keeps the separators a printed number may
/// use, so `26 954 371 827` is one run of eleven digits; a `compact` rule
/// reads a grouped run only when a label names it, as the BSN is issued
/// without a separator: its check counts as failed.
pub(super) fn digit_runs(
    body: &Body,
    lens: &[usize],
    compact: bool,
    check: Check,
) -> Vec<Candidate> {
    body.runs
        .iter()
        .filter_map(|&(start, end)| {
            let digits = ascii_digits(&body.text[start..end]);
            let shape = lens.contains(&digits.len());
            let ok = check(&digits) && (!compact || end - start == digits.len());
            shape.then(|| Candidate::new(start, end, ok))
        })
        .collect()
}

/// Every digit run whose digits number one of `lens`, the check holding only
/// when the run is printed in the `bare` shape the value is issued in: another
/// grouping is a telephone number or a reference unless a label names it.
pub(super) fn shaped_runs(
    body: &Body,
    lens: &[usize],
    bare: Shape,
    check: Check,
) -> Vec<Candidate> {
    body.runs
        .iter()
        .filter_map(|&(start, end)| {
            let raw = &body.text[start..end];
            let digits = ascii_digits(raw);
            let ok = check(&digits) && bare(raw);
            lens.contains(&digits.len())
                .then(|| Candidate::new(start, end, ok))
        })
        .collect()
}

/// Whether a run is printed without a separator.
pub(super) fn compact(raw: &str) -> bool {
    raw.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether a run holds no break and its groups have the lengths `groups`.
pub(super) fn grouped(raw: &str, groups: &[usize]) -> bool {
    let lengths: Vec<usize> = raw.split([' ', '-', '.', '/']).map(str::len).collect();
    lengths == groups
}

/// Every digit run whose digits number one of `lens`, read as
/// [`shaped_runs`] reads it, but the shape drops a run of separators that
/// holds a line break: a value issued whole and wrapped at the end of a line
/// is still whole.
pub(super) fn wrapped_runs(
    body: &Body,
    lens: &[usize],
    bare: Shape,
    check: Check,
) -> Vec<Candidate> {
    body.runs
        .iter()
        .filter_map(|&(start, end)| {
            let digits = ascii_digits(&body.text[start..end]);
            lens.contains(&digits.len()).then(|| {
                let ok = check(&digits) && bare(&unwrapped(body, start, end));
                Candidate::new(start, end, ok)
            })
        })
        .collect()
}
