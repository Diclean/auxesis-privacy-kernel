//! The cued-code recogniser: a PIN, OTP or verification code written after its
//! cue in groups.

use std::sync::LazyLock;

use regex::Regex;

use super::phrase::one_of;
use super::SCORE;
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// The cue of a short numeric code: a PIN, an OTP or a
/// passcode (group 1), whose code needs four digits, or the word `code`, six.
static CODE_CUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:(pin|otp|passcode|",
        r"codes?[ \t]+de[ \t]+(?:v[ée]rification|s[ée]curit[ée]))|codes?)\b"
    ))
    .expect("code cue compiles")
});

/// Words before a bare `code` that make it public (`zip code 75001`).
const PUBLIC_CODE_HEADS: &str =
    "zip postal post area country dialing dialling status error exit http promo discount product";
/// Words that may stand between a cue and its code (`code is`, `PIN: your`).
const CODE_FILLERS: &str =
    "is was are be will est sera your my the votre ton mon le la de du number";
/// What may follow a number to make it an amount.
const CURRENCIES: &str = "€ $ £ ¥ % eur usd gbp chf cny rmb euro euros dollar dollars yuan";
/// Bytes read for the gap before a code, for a head word, and the most digits.
const MAX_CODE_GAP: usize = 40;
const MAX_HEAD_BYTES: usize = 24;
const MAX_CODE_DIGITS: usize = 10;

/// A PIN, one-time or verification code written after its cue in groups:
/// `PIN 1234  5678`, `OTP 12 . 34 . 56`, `code: 803-143-301`. The groups are
/// joined by up to three spaces or line breaks on each side of an optional
/// dot or dash, and masked whole. A decimal, a date, an amount or a number
/// that runs on stays clear, and a date or a decimal ends the search rather
/// than falling back to its leading groups; when only the joined value is an
/// amount, its first groups are still a code (`OTP 1234  56 USD` masks
/// `1234`).
#[derive(Clone, Copy, Debug, Default)]
pub struct CuedCodeRecognizer;

impl Recognizer for CuedCodeRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Secret]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        CODE_CUE_RE
            .captures_iter(text)
            .filter_map(|cue| {
                let (whole, strong) = (cue.get(0)?, cue.get(1).is_some());
                let from = text.ceil_char_boundary(whole.start().saturating_sub(MAX_HEAD_BYTES));
                let head = text[from..whole.start()].trim_end_matches([' ', '\t', '-']);
                let head = head.rsplit(|ch: char| !ch.is_alphanumeric()).next();
                if !strong && one_of(PUBLIC_CODE_HEADS, head.unwrap_or("")) {
                    return None;
                }
                let start = code_start(text, whole.end())?;
                let end = code_end(text, start, if strong { 4 } else { 6 })?;
                Some(Span::new(
                    EntityKind::Secret,
                    start,
                    end,
                    SCORE,
                    self.name(),
                ))
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "cued_code"
    }
}

/// Where the code after a cue ending at `from` starts: punctuation and filler
/// words only, within [`MAX_CODE_GAP`] bytes.
fn code_start(text: &str, from: usize) -> Option<usize> {
    let mut at = from;
    while at < from + MAX_CODE_GAP {
        let ch = text[at..].chars().next()?;
        if ch.is_ascii_digit() {
            return Some(at);
        }
        if ch.is_alphabetic() {
            let len: usize = text[at..]
                .chars()
                .take_while(|c| c.is_alphabetic())
                .map(char::len_utf8)
                .sum();
            if !one_of(CODE_FILLERS, &text[at..at + len]) {
                return None;
            }
            at += len;
        } else if " \t\r\n:：=#-–—>*\"'“”‘’«»([".contains(ch) {
            at += ch.len_utf8();
        } else {
            return None;
        }
    }
    None
}

/// The bytes of the separator at `at` between two groups: up to three spaces
/// or line breaks, an optional `.` or `-`, up to three more; 0 for none.
fn code_separator(bytes: &[u8], at: usize) -> usize {
    let space = |from: usize| {
        bytes[from.min(bytes.len())..]
            .iter()
            .take(4)
            .take_while(|b| b.is_ascii_whitespace())
            .count()
    };
    let before = space(at);
    let mark = usize::from(matches!(bytes.get(at + before), Some(b'.' | b'-')));
    let after = if mark == 1 { space(at + before + 1) } else { 0 };
    if before > 3 || after > 3 {
        return 0;
    }
    before + mark + after
}

/// The end of the code starting at `at`: the most groups, `min` to
/// [`MAX_CODE_DIGITS`] digits, that are no decimal, date or amount and that no
/// letter or further number touches.
///
/// A value that parses as a date or as a decimal ends the search: no shorter
/// prefix of `2026-10-21` or of `1234.50` is a code either, and retrying would
/// mask `2026-` and `1234`. An amount is the one shape that does fall back to
/// the groups before it (`OTP 1234  56 USD` masks `1234`).
fn code_end(text: &str, at: usize, min: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let (mut groups, mut joints) = (Vec::new(), Vec::new());
    let (mut start, mut digits) = (at, 0);
    loop {
        let run = bytes[start..]
            .iter()
            .take(MAX_CODE_DIGITS + 1)
            .take_while(|b| b.is_ascii_digit())
            .count();
        digits += run;
        if digits > MAX_CODE_DIGITS {
            return None;
        }
        groups.push((start, start + run, digits));
        let separator = code_separator(bytes, start + run);
        if separator == 0
            || !bytes
                .get(start + run + separator)
                .is_some_and(u8::is_ascii_digit)
        {
            break;
        }
        joints.push(&text[start + run..start + run + separator]);
        start += run + separator;
    }
    let decimal = |count: usize| count == 2 && joints[0] == "." && groups[1].1 - groups[1].0 <= 2;
    // The whole run of groups read: three groups that are a date, or two that
    // are a decimal, and the value around them is not a code.
    if decimal(groups.len()) || (groups.len() == 3 && is_date(text, &groups, &joints)) {
        return None;
    }
    (1..=groups.len()).rev().find_map(|count| {
        let (_, end, digits) = groups[count - 1];
        let rest = &text[end..];
        let runs_on = rest.starts_with(char::is_alphanumeric)
            || rest.len() > 1
                && rest.starts_with([',', '/', ':'])
                && rest.as_bytes()[1].is_ascii_digit();
        let unit = rest.trim_start_matches([' ', '\u{a0}']);
        let amount = CURRENCIES.split(' ').any(|currency| {
            unit.get(..currency.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(currency))
                && !unit[currency.len()..].starts_with(|ch: char| ch.is_alphabetic())
        });
        (digits >= min && !decimal(count) && !runs_on && !amount).then_some(end)
    })
}

/// Whether three groups joined by the same `-` or `.` are a date.
fn is_date(text: &str, groups: &[(usize, usize, usize)], joints: &[&str]) -> bool {
    let field = |index: usize| {
        let (start, end, _) = groups[index];
        (end - start, text[start..end].parse::<u32>().unwrap_or(0))
    };
    let [(l0, v0), (l1, v1), (l2, v2)] = [0, 1, 2].map(field);
    let day_month = |x: u32, y: u32| (1..=31).contains(&x) && (1..=12).contains(&y);
    let either = |x, y| day_month(x, y) || day_month(y, x);
    joints[0] == joints[1]
        && matches!(joints[0], "-" | ".")
        && l1 <= 2
        && (l0 == 4 && l2 <= 2 && either(v1, v2) || l2 == 4 && l0 <= 2 && either(v0, v1))
}
