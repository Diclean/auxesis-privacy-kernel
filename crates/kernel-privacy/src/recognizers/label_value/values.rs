//! Value readers: secrets, cookies, ID numbers and passport shapes.

use crate::recognizers::secrets::linked_clause_end;

use super::links::{opening_quote, QUOTES};
use super::text::is_cjk;

/// Longest ID or health number, in bytes.
const MAX_ID: usize = 40;

/// Plain words a prose link may bring that are no value (`password, then log in`).
const FUNCTION_WORDS: &str = "which that then please but so if as when where while you your \
    it its this these we our they he she also with without because since though however \
    there their only just even still very including such sent shared provided given emailed \
    texted displayed shown available valid case sensitive different same strong weak secure \
    long short";

/// Whether `value` is a real date (`2024-10-01`, `01/10/2024`, `1.10.24`):
/// three digit groups over one kind of `-`, `/` or `.`, read year first
/// (`yyyy-mm-dd`, `yy-mm-dd`) or year last (`dd-mm-yyyy`, `mm-dd-yy`), with a
/// month of 1 to 12 and a day of 1 to 31 in one of those readings. A
/// `number`-linked label's value is never one (`licence number: 2024-10-01`);
/// `99-99-99` or `12-34-56` is no date, so it stays an ID.
pub(super) fn is_date(value: &str) -> bool {
    let Some(sep) = value.chars().find(|c| matches!(c, '-' | '/' | '.')) else {
        return false;
    };
    let groups: Vec<&str> = value.split(sep).collect();
    if groups.len() != 3
        || !groups
            .iter()
            .all(|g| (1..=4).contains(&g.len()) && g.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let lens: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    let n: Vec<u32> = groups.iter().filter_map(|g| g.parse().ok()).collect();
    let date = |month: u32, day: u32| (1..=12).contains(&month) && (1..=31).contains(&day);
    let year_first = (lens[0] == 4 || lens[0] == 2) && lens[1] <= 2 && lens[2] <= 2;
    let year_last = lens[0] <= 2 && lens[1] <= 2 && (lens[2] == 4 || lens[2] <= 2);
    year_first && date(n[1], n[2]) || year_last && (date(n[1], n[0]) || date(n[0], n[1]))
}
/// The words of a passport label, folded: the spaced CN passport
/// number is read behind one of these and behind no other ID label.
const PASSPORT_WORDS: &str = "passport passportno passportnumber passports passeport \
    pasaporte 护照 护照号 护照号码";

/// The end of a secret value at `start` on a line ending at `line`, and how far the
/// read went. A quoted value runs to its closing quote, or the line end when it has
/// none. Else one token, secret-shaped, or after a prose link a plain word that is
/// no stopword, then its clause. No byte cap: the registry splits a
/// long span.
pub(super) fn secret(
    text: &str,
    start: usize,
    line: usize,
    prose: Option<bool>,
) -> (Option<usize>, usize) {
    let rest = &text[start..line];
    if rest.starts_with(['⟦', '[']) {
        return (None, start);
    }
    if let Some(quote) = opening_quote(text, start) {
        let close = rest.find(|c: char| c == quote || QUOTES.contains(c) && c != '\'');
        let value = rest[..close.unwrap_or(rest.len())].trim_end();
        let end = start + value.len();
        return ((value.chars().count() >= 4).then_some(end), end);
    }
    let cjk = rest.starts_with(is_cjk);
    let token_end = rest
        .find(|c: char| c.is_whitespace() || "，。；、）」』|".contains(c) || (!cjk && is_cjk(c)))
        .unwrap_or(rest.len());
    let token =
        rest[..token_end].trim_end_matches(|c: char| ",;:)]}>*`".contains(c) || QUOTES.contains(c));
    let symbol = |c: char| !c.is_alphanumeric() && !".-'’".contains(c);
    // An HTML tag or attribute (`id="pin"`, `Entry</title>`) is markup, not a value.
    let markup = token.contains(['<', '>']) || token.contains("=\"") || token.contains("='");
    let long = token.chars().count() >= 4;
    let shaped = token.chars().any(|c| c.is_ascii_digit()) || token.chars().any(symbol);
    let word = token.trim_end_matches(['.', '!', '?']);
    let plain = !FUNCTION_WORDS
        .split(' ')
        .any(|w| w.eq_ignore_ascii_case(word));
    let end = start + token.len();
    let plain = match prose {
        Some(true) => plain,
        // After a bare comma a plain word is an apposition: its clause is that word
        // (`the password, sunflowerfield, opens it`), never a list (`passwords, two-
        // factor authentication`).
        Some(false) => plain && linked_clause_end(text, start, end, line) == Some(end),
        None => false,
    };
    if markup || !long || !(shaped || plain) {
        return (None, start + token_end);
    }
    if prose.is_none() {
        return (Some(end), end);
    }
    let clause = linked_clause_end(text, start, end, line);
    (clause, clause.unwrap_or(end))
}

/// The rest of the line at `start`, up to `line`, as a cookie header's value.
pub(super) fn cookie(text: &str, start: usize, line: usize) -> Option<usize> {
    let value = text[start..line].trim_end();
    (!value.starts_with(['⟦', '['])).then_some(start + value.len())
}

/// The end of an ID or record number at `start`: alphanumeric groups joined by
/// one of `-./` or one space (a spaced group must hold a digit), with at least
/// `min` alphanumerics, two of them digits.
///
/// Main's own reading comes first, so `Tax ID no1234` is six alphanumerics —
/// the sign's letters are two of them — and reads exactly as it reads on main.
/// Only a sign main's reading cannot see past (`n°12AB34567`, where `°` ends
/// the alphanumeric run) is read from behind the sign, and there the sign's own
/// letters count toward `min` as well. The mask starts at the
/// label's own `start` either way, so it covers the sign and the digits behind
/// it.
pub(super) fn number(text: &str, start: usize, min: usize) -> Option<usize> {
    number_from(text, start, min, 0).or_else(|| match glued_sign(text, start) {
        0 => None,
        sign => number_from(
            text,
            start + sign,
            min,
            text.as_bytes()[start..start + sign]
                .iter()
                .filter(|b| b.is_ascii_alphanumeric())
                .count(),
        ),
    })
}

/// [`number`] read from `from`, with `carry` alphanumerics already read in front
/// of it (the letters of a glued sign) counted toward `min`.
fn number_from(text: &str, from: usize, min: usize, carry: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let (mut at, mut end, mut alnum, mut digits) = (from, from, carry, 0);
    while at < bytes.len() && at - from <= MAX_ID {
        let run = bytes[at..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric())
            .count();
        if run == 0 {
            break;
        }
        let group_digits = bytes[at..at + run]
            .iter()
            .filter(|b| b.is_ascii_digit())
            .count();
        // A spaced group joins only a value that already holds a digit, so a word
        // before a year stays clear (`ID card renewal 2026`).
        if at > from && bytes[at - 1] == b' ' && (group_digits == 0 || digits == 0) {
            break;
        }
        (alnum, digits, end) = (alnum + run, digits + group_digits, at + run);
        match bytes.get(end..end + 2) {
            Some([b'-' | b'.' | b'/' | b' ', next]) if next.is_ascii_alphanumeric() => at = end + 1,
            _ => break,
        }
    }
    let boundary = !text[end..].starts_with(char::is_alphanumeric);
    (alnum >= min && digits >= 2 && boundary).then_some(end)
}

/// The bytes of the number sign glued to `start` (`n°`, `nº`, `no`), when a
/// digit follows it. A word that only starts with a sign is no sign at all
/// (`nothing`, `notes`), so `Tax ID nothing12` keeps main's reading.
fn glued_sign(text: &str, start: usize) -> usize {
    let rest = &text[start..];
    let sign = match rest.chars().next() {
        Some('n' | 'N') => rest[1..]
            .chars()
            .next()
            .filter(|c| matches!(c, '°' | 'º' | 'ª' | 'o' | 'O'))
            .map_or(0, |c| 1 + c.len_utf8()),
        _ => 0,
    };
    if sign > 0 && rest[sign..].starts_with(|c: char| c.is_ascii_digit()) {
        sign
    } else {
        0
    }
}

/// The end of a CN passport number written spaced behind a **passport** label:
/// one or two capital letters, then two groups of four digits
/// (`E 1234 5678`). The shape is a passport number's, so a tax or a
/// licence label does not claim it (`tax id: E 1234 5678` is a tax number and
/// stays clear). It is read by hand because [`number`] joins a spaced group only
/// to a value that already holds a digit, and the leading `E` holds none.
pub(super) fn spaced_passport(text: &str, label: &str, start: usize) -> Option<usize> {
    if !passport_label(label) {
        return None;
    }
    let bytes = text.as_bytes();
    let letters = count_upper(bytes, start);
    if !(1..=2).contains(&letters) {
        return None;
    }
    let mut end = start + letters;
    for _ in 0..2 {
        // Each group is one blank, then exactly four digits.
        if bytes.get(end) != Some(&b' ') || count_digits(bytes, end + 1) != 4 {
            return None;
        }
        end += 5;
    }
    (!text[end..].starts_with(char::is_alphanumeric)).then_some(end)
}

/// Whether a folded label holds a passport word, so a spaced CN passport number
/// behind it is one (`passport`, `passport number`, `passportno`, `passeport`,
/// `numero de passeport`, `护照`, `护照号`, `护照号码`).
fn passport_label(label: &str) -> bool {
    label
        .split(|c: char| !c.is_alphanumeric())
        .any(|word| PASSPORT_WORDS.split(' ').any(|p| p == word))
}

/// The run of ASCII capitals at `at`, in bytes.
fn count_upper(bytes: &[u8], at: usize) -> usize {
    bytes
        .get(at..)
        .unwrap_or_default()
        .iter()
        .take_while(|b| b.is_ascii_uppercase())
        .count()
}

/// The run of ASCII digits at `at`, in bytes.
fn count_digits(bytes: &[u8], at: usize) -> usize {
    bytes
        .get(at..)
        .unwrap_or_default()
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count()
}
