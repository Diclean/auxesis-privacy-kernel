//! The bounded link between a label and its value.

use super::text::{ends_word, is_cjk};

/// Longest link between a label and its value, a blank run counted once.
const MAX_LINK: usize = 24;
/// Longest link in raw bytes, so a padded table cell still links.
const MAX_LINK_RAW: usize = 64;

/// Words that may sit between a label and its value. A number word also counts
/// as the strong link a `punct` label needs.
const LINKS: &str = "is was are were be been might may will would should could must now still \
    currently set changed updated to est etait sera devient ist lautet war je c'est";
/// Links only a health number, a blood group or an ID takes (`a blood type of O+`,
/// `a tax ID of 98-…`, `ma cni c'est …`): a secret after `of` stays as main.
const HEALTH_LINKS: &str = "of such as like c'est";

/// The words that open a clause a secret label's value follows (`password for the
/// office is …`, `wagwoord vir die wifi is …`, `geslo za e-pošto: …`): only a
/// shaped value is read after one, never a plain word.
const SECRET_HEADS: &str = "for vir za pour";

/// The links after which a plain word is a value (`might be`, `set to`, `est`):
/// English and French only, the languages of the clause-tail stopwords.
const PROSE_LINKS: &str = "is was are were be been set changed updated est etait sera";
const NUMBER_WORDS: &str =
    "no nr n° nº num number numero nummer nommer szam szama stevilka 号 号码 號碼 是 为 為";

/// Words that make a `number`-linked label a business's, right before it.
const BUSINESS_WORDS: &str = "certificate software product business trade company vendor \
    export import site server app seat volume";
/// Business words read in an aside only, not before a label:
/// `the corporate licence number …` stays masked as on main.
const BUSINESS_ASIDES: [&str; 4] = ["corporate", "commercial", "organisation", "organization"];

pub(super) const QUOTES: &str = "\"'`“”‘’«»„「」『』";

/// Skip the link after a label ending at `from` in `folded`: the value's
/// folded offset and whether a strong link (`:`, `=`, `#`, a number word) was
/// crossed (a table cell `|` is decoration), and the prose link after which a
/// plain word is a value: `Some(true)` for a word (`is`, `be`, `set`, `changed`),
/// `Some(false)` for a bare comma. `None` past the bound or a line. A `health`
/// or ID label (`wide`) also crosses [`HEALTH_LINKS`] and a `for … is` clause.
///
/// An opening parenthesis is decoration for a `wide` label only
/// (`driver_license_number (D37-…)`). Behind a secret or cookie
/// label it is the first byte of the value, exactly as on main: `api_key
/// (smith…)` masks from the `(`.
///
/// Behind an ID label (`aside`), one [`aside_end`] aside is crossed whole, so a
/// `:` after it is the strong link (`TIN (if applicable): …`) and its words are
/// no link (`(as applicable)`); the last field says whether one was crossed, or
/// a secret label's [`SECRET_HEADS`] clause (no prose link counts after it).
pub(super) fn link(
    folded: &str,
    from: usize,
    wide: bool,
    aside: bool,
) -> Option<(usize, bool, Option<bool>, bool)> {
    let (mut at, mut used, mut strong, mut lines) = (from, 0, false, 0);
    let mut crossed = false;
    let mut prose = None;
    while at < folded.len() && used <= MAX_LINK && at - from <= MAX_LINK_RAW {
        let rest = &folded[at..];
        let ch = rest.chars().next()?;
        if ch.is_whitespace() {
            let run = rest.len() - rest.trim_start().len();
            lines += rest[..run].matches('\n').count();
            if lines > 1 {
                return None;
            }
            (at, used) = (at + run, used + 1);
            continue;
        }
        if aside && !crossed && ch == '(' {
            if let Some(end) = aside_end(folded, at + 1) {
                (at, used, crossed) = (end, used + 1, true);
                continue;
            }
        }
        if matches!(ch, ':' | '：' | '=' | '#') {
            strong = true;
        } else if matches!(ch, ',' | '，') {
            prose = prose.or(Some(false));
        } else if !matches!(ch, '*' | '|' | '–' | '—' | '>')
            && !(wide && ch == '(')
            && !QUOTES.contains(ch)
        {
            let word = |w: &&str| {
                rest.starts_with(*w) && (w.ends_with(is_cjk) || ends_word(&rest[w.len()..]))
            };
            if let Some(number) = NUMBER_WORDS.split(' ').find(word) {
                let dot = usize::from(rest[number.len()..].starts_with('.'));
                (at, used, strong) = (at + number.len() + dot, used + number.len() + dot, true);
                continue;
            }
            if wide && word(&"for") {
                if let Some((len, colon)) = for_clause(&rest[3..]) {
                    (at, used, strong) = (at + 3 + len, used + 4, strong || colon);
                    continue;
                }
            }
            if let Some(head) = SECRET_HEADS.split(' ').filter(|_| !wide).find(word) {
                if let Some((len, colon)) = for_clause(&rest[head.len()..]) {
                    let skip = head.len() + len;
                    (at, used, strong, crossed) =
                        (at + skip, used + head.len() + 1, strong || colon, true);
                    continue;
                }
            }
            let wide_link = || HEALTH_LINKS.split(' ').filter(|_| wide).find(word);
            if let Some(link) = LINKS.split(' ').find(word).or_else(wide_link) {
                if !crossed && PROSE_LINKS.split(' ').any(|prose| prose == link) {
                    prose = Some(true);
                }
                (at, used) = (at + link.len(), used + link.len());
                continue;
            }
            return Some((at, strong, prose, crossed));
        }
        (at, used) = (at + ch.len_utf8(), used + ch.len_utf8());
    }
    None
}

/// The folded offset past a short aside whose `(` ends right before `at`
/// one to thirty letters, blanks, `'`, `-` or `/`, then `)`. No
/// digit, so a value in parentheses stays the value, and no business word
/// (`licence number (business): …` is a business's). At most 31 characters.
fn aside_end(folded: &str, at: usize) -> Option<usize> {
    let rest = &folded[at..];
    let len = rest
        .char_indices()
        .take(31)
        .find(|&(_, c)| !(c.is_alphabetic() || matches!(c, ' ' | '\'' | '’' | '-' | '/')))
        .filter(|&(_, c)| c == ')')?
        .0;
    let aside = &rest[..len];
    let words = || {
        aside
            .split(|c: char| !c.is_alphabetic())
            .filter(|w| !w.is_empty())
    };
    let business = |w: &str| {
        BUSINESS_WORDS
            .split(' ')
            .chain(BUSINESS_ASIDES)
            .any(|b| b == w)
    };
    (words().next().is_some() && !words().any(business)).then_some(at + len + 1)
}

/// Whether a number word comes first in `rest`, past blanks (`licence number …`,
/// `licence no. …`, `licence n°12AB34567`): a word that only starts
/// with one (`licence notes`) is none. A business word right before the label
/// makes it a business's (`the certificate license number …`).
///
/// The business word is read in the label's own field only: a line break, `:`,
/// `;` or `.` ends the field before (`Purpose: business\nLicence number …` is
/// the owner's). One line break may stand inside the label
/// (`licence\nnumber: …`, `licence\r\nnumber: …`).
pub(super) fn numbered(before: &str, rest: &str) -> bool {
    let near = &before[before.floor_char_boundary(before.len().saturating_sub(32))..];
    let field = near.rsplit(['\n', ':', ';', '.']).next().unwrap_or(near);
    let word = field
        .split(|c: char| !c.is_alphanumeric())
        .rev()
        .find(|w| !w.is_empty());
    if word.is_some_and(|word| BUSINESS_WORDS.split(' ').any(|w| w == word)) {
        return false;
    }
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = rest
        .strip_prefix("\r\n")
        .or_else(|| rest.strip_prefix('\n'))
        .map_or(rest, |tail| tail.trim_start_matches([' ', '\t']));
    NUMBER_WORDS.split(' ').any(|word| {
        rest.strip_prefix(word)
            .is_some_and(|tail| ends_word(tail) || tail.starts_with(|c: char| c.is_ascii_digit()))
    })
}

/// After a health label's `for` (or a secret label's [`SECRET_HEADS`] word), one
/// to three words then `is`, `was`, `je`, `est` or `:` (`medical record number for
/// this donor is …`): the folded bytes up to and with that link, and whether it
/// was a `:`. `None` for any other shape.
fn for_clause(rest: &str) -> Option<(usize, bool)> {
    let blank = |s: &str| s.len() - s.trim_start_matches([' ', '\t']).len();
    let mut at = 0;
    for _ in 0..3 {
        let space = blank(&rest[at..]);
        let word = rest[at + space..]
            .find(|c: char| !c.is_alphanumeric() && c != '\'')
            .unwrap_or(rest.len() - at - space);
        if space == 0 || word == 0 {
            return None;
        }
        at += space + word;
        let skip = blank(&rest[at..]);
        let after = &rest[at + skip..];
        if after.starts_with(':') {
            return Some((at + skip + 1, true));
        }
        let link = ["is", "was", "je", "est"]
            .into_iter()
            .find(|w| after.starts_with(w));
        if let Some(link) = link.filter(|w| skip > 0 && ends_word(&after[w.len()..])) {
            return Some((at + skip + link.len(), false));
        }
    }
    None
}

/// The quote char just before `start`, when it opens the value: it follows a
/// blank or a separator, so the quote closing `'Change PIN'` never opens one.
pub(super) fn opening_quote(text: &str, start: usize) -> Option<char> {
    let mut before = text[..start].chars().rev();
    let quote = before.next().filter(|c| QUOTES.contains(*c))?;
    let opens = |c: char| c.is_whitespace() || ":=(,[{：".contains(c);
    before.next().is_none_or(opens).then_some(quote)
}
