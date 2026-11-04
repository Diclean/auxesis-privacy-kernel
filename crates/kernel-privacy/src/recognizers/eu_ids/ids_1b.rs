//! Poland, Portugal, Austria, Ireland and Sweden.

use crate::normalize::ascii_digits;

use super::checks::{at_sv_ok, pl_pesel_ok, pt_nif_ok, se_personnummer_ok};
use super::cues::IE_CUES;
use super::letters::{letter_after, spaced_only};
use super::scan::{compact, grouped, has_cue, shaped_runs};
use super::{Body, Candidate};

/// The Polish PESEL: eleven digits, issued without a separator.
pub(super) fn pl_candidates(body: &Body) -> Vec<Candidate> {
    shaped_runs(body, &[11], compact, pl_pesel_ok)
}

/// The Portuguese NIF: nine digits, mod 11. Nine digits with a mod-11 check
/// match one number in eleven, so the rule reads a NIF only after a label.
pub(super) fn pt_candidates(body: &Body) -> Vec<Candidate> {
    shaped_runs(body, &[9], |_| false, pt_nif_ok)
}

/// The Austrian SV-Nr: ten digits, `NNNC DDMMYY`, printed whole or in these
/// two groups.
pub(super) fn at_candidates(body: &Body) -> Vec<Candidate> {
    shaped_runs(
        body,
        &[10],
        |raw| compact(raw) || grouped(raw, &[4, 6]),
        at_sv_ok,
    )
}

/// The Swedish personnummer: `YYMMDD-NNNC` or `YYYYMMDD-NNNC`, Luhn over the
/// last ten digits; a `+` stands for a person past a hundred.
pub(super) fn se_candidates(body: &Body) -> Vec<Candidate> {
    let bare = |raw: &str| compact(raw) || grouped(raw, &[6, 4]) || grouped(raw, &[8, 4]);
    let mut found = shaped_runs(body, &[10, 12], bare, se_personnummer_ok);
    let bytes = body.text.as_bytes();
    for &(start, end) in &body.runs {
        let after = end + 5;
        let plus = end - start == 6 || end - start == 8;
        if !plus
            || bytes.get(end) != Some(&b'+')
            || !body.text.get(end + 1..after).is_some_and(compact)
            || bytes.get(after).is_some_and(u8::is_ascii_digit)
            || !compact(&body.text[start..end])
        {
            continue;
        }
        let digits = ascii_digits(&body.text[start..after]);
        found.push(Candidate::new(start, after, se_personnummer_ok(&digits)));
    }
    found
}

/// The Irish PPSN: seven digits, the mod-23 check letter and an optional
/// second letter, which counts in the check.
pub(super) fn ie_candidates(body: &Body) -> Vec<Candidate> {
    let bytes = body.text.as_bytes();
    let mut found = Vec::new();
    for &(start, end) in &body.runs {
        if end - start != 7 || !compact(&body.text[start..end]) {
            continue;
        }
        // The check letter stands after one separator, or after a loose gap:
        // up to two spaces, a slash, a dot or a dash, and up to two spaces.
        let (at, loose) = match letter_after(body, end) {
            Some(at) => (at, false),
            None => match ie_loose_letter(bytes, end) {
                Some(at) => (at, true),
                None => continue,
            },
        };
        let digits = &body.text[start..end];
        let check = bytes[at].to_ascii_uppercase();
        // Two letters when the check holds over the second, or when two
        // letters stand alone and neither reading holds; else one.
        let second = bytes.get(at + 1).copied().filter(u8::is_ascii_alphabetic);
        let single = ie_letter(digits, None) == check;
        let pair_alone = !bytes.get(at + 2).is_some_and(u8::is_ascii_alphabetic);
        let (stop, ok) = match second {
            Some(second) if ie_letter(digits, Some(second)) == check => (at + 2, true),
            Some(_) if !single && pair_alone => (at + 2, false),
            _ => (at + 1, single),
        };
        // Letters glued to more letters are a word, unless the check holds,
        // a hyphen, a dot or nothing stands before them, and nothing is glued
        // before the digits: a token glued on both sides is a machine line,
        // unless a label names it.
        let glued = bytes.get(stop).is_some_and(u8::is_ascii_alphabetic);
        let prefixed = start > 0
            && bytes[start - 1].is_ascii_alphanumeric()
            && !has_cue(body.text, start, IE_CUES);
        if glued && (!ok || prefixed || loose || at > end && spaced_only(bytes, end, at)) {
            continue;
        }
        found.push(Candidate::new(start, stop, ok));
    }
    found
}

/// The place of the PPSN letter after a loose gap from `end`: up to two
/// spaces or tabs, at most one slash, dot or dash, and up to two spaces or tabs.
fn ie_loose_letter(bytes: &[u8], end: usize) -> Option<usize> {
    let spaces = |from: usize| {
        let count = bytes[from.min(bytes.len())..]
            .iter()
            .take(3)
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .count();
        (count <= 2).then_some(from + count)
    };
    let mut at = spaces(end)?;
    if bytes
        .get(at)
        .is_some_and(|byte| matches!(byte, b'/' | b'.' | b'-'))
    {
        at = spaces(at + 1)?;
    }
    (at > end && bytes.get(at).is_some_and(u8::is_ascii_alphabetic)).then_some(at)
}

/// The Irish check letter: the digits weighted 8 to 2, the second letter
/// weighted 9 (`W` counting 0), modulo 23; 0 is `W`.
fn ie_letter(digits: &str, second: Option<u8>) -> u8 {
    let mut sum: u32 = digits
        .bytes()
        .zip((2..=8).rev())
        .map(|(byte, weight)| u32::from(byte - b'0') * weight)
        .sum();
    if let Some(letter) = second.map(|byte| byte.to_ascii_uppercase()) {
        sum += 9 * if letter == b'W' {
            0
        } else {
            u32::from(letter - b'A' + 1)
        };
    }
    match sum % 23 {
        0 => b'W',
        rest => b'A' + rest as u8 - 1,
    }
}
