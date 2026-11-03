//! EU-KERNEL-1a: Germany, Spain, Italy, the Netherlands and Belgium.

use crate::normalize::ascii_digits;

use super::checks::{be_national_ok, de_steuer_id_ok, nl_bsn_ok};
use super::letters::{es_separator, es_separator_run_start, letter_after, spaced_only};
use super::scan::digit_runs;
use super::{Body, Candidate, IT_LENGTH};

/// The shortest hex digest: an md5. A run of hex digits this long is a digest,
/// and a window of it is not a codice fiscale.
const HEX_DIGEST_MIN: usize = 32;

/// The positions of the letters of a codice fiscale: the six of the name, the
/// letter of the month and the letter of the place.
const IT_LETTERS: [usize; 8] = [0, 1, 2, 3, 4, 5, 8, 11];

/// The positions of the digits of a codice fiscale: the year, the day and the
/// three digits of the place.
const IT_DIGITS: [usize; 7] = [6, 7, 9, 10, 12, 13, 14];

/// The position of the control letter of a codice fiscale.
const IT_CONTROL: usize = 15;

/// The German Steuer-ID: eleven digits, ISO 7064 MOD 11,10.
pub(super) fn de_candidates(body: &Body) -> Vec<Candidate> {
    digit_runs(body, &[11], false, de_steuer_id_ok)
}

/// The Dutch BSN: nine consecutive digits, the eleven-proof. A grouped run of
/// nine digits is a telephone number or a reference unless a label names it.
pub(super) fn nl_candidates(body: &Body) -> Vec<Candidate> {
    digit_runs(body, &[9], true, nl_bsn_ok)
}

/// The Belgian national number: eleven digits (`YY MM DD XXX CC`) or twelve
/// with the century in front, as a birth after 2000 is written.
pub(super) fn be_candidates(body: &Body) -> Vec<Candidate> {
    digit_runs(body, &[11, 12], false, be_national_ok)
}

/// The Spanish DNI (eight digits and a letter) and NIE (X, Y or Z, seven
/// digits and a letter), the letter being the mod-23 check.
///
/// The letter may stand after a separator: a hyphen, a space, a dot or a
/// single line break, the normaliser folding a break to a space. A run of
/// separators that holds a line break is one separator, so the letter may
/// stand after the whole run. The NIE keeps its letter before the digits, one
/// separator away.
pub(super) fn es_candidates(body: &Body) -> Vec<Candidate> {
    let bytes = body.text.as_bytes();
    let mut found = Vec::new();
    for &(start, end) in &body.runs {
        let digits = ascii_digits(&body.text[start..end]);
        // The letter of a DNI or a NIE stands after the digits, or after one
        // separator.
        let Some((letter_at, glued)) = es_letter_at(body, end) else {
            continue;
        };
        let letter = bytes[letter_at].to_ascii_uppercase();
        // A DNI: eight digits and the letter. A NIE: the letter X, Y or Z
        // stands before the seven digits and stands for 0, 1 or 2.
        let (from, number) = match digits.len() {
            8 => (start, digits.parse::<u32>().unwrap_or(u32::MAX)),
            7 => {
                let Some(prefix_at) = es_nie_at(body, start) else {
                    continue;
                };
                let head = u32::from(bytes[prefix_at].to_ascii_uppercase() - b'X') * 10_000_000;
                (prefix_at, head + digits.parse::<u32>().unwrap_or(0))
            }
            _ => continue,
        };
        let ok = ES_LETTERS[(number % 23) as usize] == letter;
        if glued && !ok {
            continue;
        }
        found.push(Candidate::new(from, letter_at + 1, ok));
    }
    found
}

/// The place of the control letter of a DNI or a NIE: right after the digits,
/// or after one separator.
///
/// A letter that stands alone is a control letter; a letter that starts the
/// next word is not, for the digits of a date are followed by a word. A run of
/// separators that holds a line break is one separator, so the letter may
/// stand after the whole run. A letter glued to a suffix after a hyphen or a
/// dot comes back `glued`: it is the control letter only when the check holds.
fn es_letter_at(body: &Body, end: usize) -> Option<(usize, bool)> {
    let bytes = body.text.as_bytes();
    let at = letter_after(body, end)?;
    if at == end {
        return Some((end, false));
    }
    let alone = !bytes
        .get(at + 1)
        .is_some_and(|after| after.is_ascii_alphabetic());
    if alone {
        return Some((at, false));
    }
    // A letter glued to a suffix after a hyphen or a dot may be the control
    // letter of a value glued to prose; after spaces alone it starts a word.
    (!spaced_only(bytes, end, at)).then_some((at, true))
}

/// The place of the letter X, Y or Z of a NIE: right before the digits, or
/// before one separator. A run of separators that holds a line break is one
/// separator, so the letter may stand before the whole run.
fn es_nie_at(body: &Body, start: usize) -> Option<usize> {
    let bytes = body.text.as_bytes();
    let at = start.checked_sub(1)?;
    if matches!(bytes[at].to_ascii_uppercase(), b'X' | b'Y' | b'Z') {
        return Some(at);
    }
    if !es_separator(bytes[at]) {
        return None;
    }
    // The run of separators that ends at the digits: the letter stands before
    // it. A run of more than one separator is one separator only when it
    // holds a line break.
    let run_start = es_separator_run_start(bytes, at);
    if at > run_start && !body.holds_break(run_start, at + 1) {
        return None;
    }
    let before = run_start.checked_sub(1)?;
    matches!(bytes[before].to_ascii_uppercase(), b'X' | b'Y' | b'Z').then_some(before)
}

/// The Italian codice fiscale: sixteen characters — six letters, two digits, a
/// letter for the month, two digits, a letter for the place, three digits and
/// the control letter. A digit replaced by a letter of the omocodia keeps the
/// shape.
pub(super) fn it_candidates(body: &Body) -> Vec<Candidate> {
    let bytes = body.text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphanumeric() {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_alphanumeric() {
            index += 1;
        }
        // Every sixteen-character window of the run: a value glued to a prefix
        // or a suffix is one value too. A hex digest is not a codice fiscale:
        // masking a window of it corrupts the digest.
        if index - start < IT_LENGTH || is_hex_digest(&bytes[start..index]) {
            continue;
        }
        for at in start..=index - IT_LENGTH {
            if let Some(ok) = it_cf_check(&bytes[at..at + IT_LENGTH]) {
                found.push(Candidate::new(at, at + IT_LENGTH, ok));
            }
        }
    }
    found
}

/// Whether an alphanumeric run is a hex digest: [`HEX_DIGEST_MIN`] hex digits
/// or more, and nothing else.
fn is_hex_digest(run: &[u8]) -> bool {
    run.len() >= HEX_DIGEST_MIN && run.iter().all(u8::is_ascii_hexdigit)
}

/// The letters a Spanish DNI or NIE number ends with.
const ES_LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// The values of the odd positions of a codice fiscale, as letters.
const IT_ODD: &str = "BAFHJNPRTVBAFHJNPRTVCESULDGIMOQKWZYX";

/// The values of the even positions: a digit and a letter stand for themselves.
const IT_EVEN: &str = "ABCDEFGHIJABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// The letters of the omocodia: a digit of a codice fiscale replaced by its
/// letter, `0` to `9` in this order.
const IT_OMOCODIA: &[u8; 10] = b"LMNPQRSTUV";

/// The Italian control letter: the odd and even tables over the first fifteen
/// characters, modulo 26. The remainder stands for the letter `A` to `Z`: the
/// control letter is a letter, never a digit. `written` reads a letter of the
/// omocodia as the letter it is, as the official rule does; otherwise it
/// stands for the digit it replaced.
fn it_check_char(code: &[u8], written: bool) -> u8 {
    let mut sum = 0u32;
    for (index, &byte) in code.iter().enumerate() {
        let table = if index % 2 == 0 { IT_ODD } else { IT_EVEN };
        sum += (table.as_bytes()[it_table_index(index, byte, written)] - b'A') as u32;
    }
    b'A' + (sum % 26) as u8
}

/// The place of a character of a codice fiscale in the table of its position:
/// a digit stands for itself, a letter for its place in the alphabet plus
/// ten, and a letter of the omocodia for the digit it replaced unless it is
/// read as `written`.
fn it_table_index(at: usize, byte: u8, written: bool) -> usize {
    let byte = byte.to_ascii_uppercase();
    if byte.is_ascii_digit() {
        return usize::from(byte - b'0');
    }
    match it_omocodia(byte) {
        // A digit of the omocodia stands for the digit it replaced.
        Some(digit) if !written && IT_DIGITS.contains(&at) => digit,
        _ => (usize::from(byte.saturating_sub(b'A')) + 10).min(35),
    }
}

/// The digit a letter of the omocodia stands for.
fn it_omocodia(byte: u8) -> Option<usize> {
    let byte = byte.to_ascii_uppercase();
    IT_OMOCODIA.iter().position(|&letter| letter == byte)
}

/// The shape of an Italian codice fiscale and the verdict of its control
/// letter. `None` when the sixteen characters are not shaped like one.
///
/// The shape is six letters, two digits, the letter of the month, two digits,
/// the letter of the place, three digits and the control letter. A digit
/// replaced by a letter of the omocodia keeps the shape, and the control
/// letter is computed over the letters as written, the official rule; the
/// reading over the digit it replaced holds too.
fn it_cf_check(code: &[u8]) -> Option<bool> {
    if code.len() != IT_LENGTH {
        return None;
    }
    let upper = |at: usize| code[at].to_ascii_uppercase();
    if !IT_LETTERS.iter().all(|&at| upper(at).is_ascii_alphabetic()) {
        return None;
    }
    if !IT_DIGITS
        .iter()
        .all(|&at| upper(at).is_ascii_digit() || it_omocodia(upper(at)).is_some())
    {
        return None;
    }
    if !upper(IT_CONTROL).is_ascii_alphabetic() {
        return None;
    }
    let head = &code[..IT_CONTROL];
    let control = upper(IT_CONTROL);
    Some(control == it_check_char(head, true) || control == it_check_char(head, false))
}
