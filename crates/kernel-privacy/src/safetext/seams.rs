//! The seams of [`SafeText::join`](super::SafeText::join), each read again by
//! the private recognisers with the tokens and markers the kernel wrote (its
//! marks) as fixed stand-ins, never edited. A value found that the mode hides,
//! or clear text a seam ties to a mark, becomes a fixed marker.

use std::cell::LazyCell;
use std::iter::once;
use std::sync::LazyLock;

use kernel_core::privacy::GrantPolicy;

use super::detector::Detector;
use super::prohibited::{is_hash_fragment, removal_text};
use super::residue::MASKED_STAND_IN;
use super::tokens::session_token_len;
use crate::anonymize::{kind_of_token, PLACEHOLDER_OPEN};
use crate::public_terms::{fold, PublicTerms};
use crate::recognizer::span_is_well_formed;
use crate::recognizers::secrets::value_too_long;
use crate::span::{EntityKind, Span};

/// A byte range of a text.
pub(super) type Mark = (usize, usize);
/// Byte ranges, sorted and disjoint, of the tokens and markers the kernel wrote.
pub(super) type Marks = Vec<Mark>;
/// A range a join hides, and the marker it writes there.
type Piece = (Mark, &'static str);

/// What a join writes in place of clear text whose class has no marker.
const VALUE_REMOVED: &str = "[value removed]";
/// What a join issues when it cannot hide what crosses a seam.
const WITHHELD: &str = "[auxesis: withheld]";
/// The characters read each side of a seam, out to whole words.
const WINDOW_CHARS: usize = 40;
/// The longest run a join ties to a mark.
const MAX_RUN_BYTES: usize = 512;
/// The longest key a join reads on from a key mark, in bytes.
const MAX_KEY_BYTES: usize = 16 * 1024;
/// The most words a join reads on from an address mark.
const MAX_ADDRESS_WORDS: usize = 8;
/// The most blank characters a seam rule reads across, and the most bytes of
/// one address word: past them the rule stops, so a join stays linear.
const MAX_BLANKS: usize = 4096;

/// The byte length of the blanks `text` ends with (`back`) or starts with,
/// `None` past [`MAX_BLANKS`] characters.
fn blanks(text: &str, back: bool) -> Option<usize> {
    let mut chars: Box<dyn Iterator<Item = char>> = match back {
        true => Box::new(text.chars().rev()),
        false => Box::new(text.chars()),
    };
    let mut len = 0;
    for _ in 0..=MAX_BLANKS {
        match chars.next() {
            Some(ch) if ch.is_whitespace() => len += ch.len_utf8(),
            _ => return Some(len),
        }
    }
    None
}
/// The built-in public terms an address may end with, as on 0.1.5 (their
/// capitals, and brands kept so no join shows more than it did).
static PUBLIC: LazyLock<PublicTerms> = LazyLock::new(PublicTerms::builtin);
/// Major cities past the capitals of [`PUBLIC`] that an address may end with.
const CITIES: &str = "lyon lille marseille toulouse nice nantes strasbourg montpellier \
    bordeaux rennes reims grenoble dijon angers nîmes toulon brest metz rouen caen nancy \
    orléans tours limoges amiens perpignan besançon mulhouse avignon clermont-ferrand \
    manchester birmingham liverpool leeds glasgow edinburgh bristol sheffield cardiff belfast \
    hamburg munich münchen cologne köln frankfurt stuttgart düsseldorf leipzig dresden \
    barcelona valencia seville sevilla milan milano naples napoli turin torino florence \
    porto rotterdam antwerp antwerpen ghent gent liège geneva genève zurich zürich basel \
    lausanne bern luxembourg debrecen szeged pécs győr miskolc ljubljana maribor kraków \
    gdańsk wrocław brno bratislava zagreb split durban bloemfontein";
static CITY_FOLDS: LazyLock<Vec<String>> =
    LazyLock::new(|| CITIES.split_whitespace().map(fold).collect());
/// Words on the line above a base64 block that name a key.
const KEY_WORDS: [&str; 7] = ["key", "secret", "token", "password", "passphrase", "private", "credential"];

/// The marks of a text a tokenising gate issued: it doubles a typed `⟦`.
pub(super) fn token_marks(text: &str) -> Marks {
    let (mut marks, mut at, open) = (Vec::new(), 0, PLACEHOLDER_OPEN.len_utf8());
    while let Some(offset) = text[at..].find(PLACEHOLDER_OPEN) {
        let start = at + offset;
        let doubled = text[start + open..].starts_with(PLACEHOLDER_OPEN);
        let len = session_token_len(&text[start..]).filter(|_| !doubled);
        marks.extend(len.map(|len| (start, start + len)));
        at = start + len.unwrap_or(if doubled { 2 * open } else { open });
    }
    marks
}

/// The join of `text`, read again 4, then 16 times wider at an edge, or [`WITHHELD`].
pub(super) fn mend(
    text: &str,
    marks: &[Mark],
    seams: &[usize],
    policy: GrantPolicy,
    scan: &dyn Detector,
) -> (String, Marks) {
    let mut pieces = Vec::new();
    for &seam in seams {
        let framed = LazyCell::new(|| framed(text, seam));
        let read = [1, 4, 16]
            .into_iter()
            .map(|times| {
                let at = window(text, marks, seam, times * WINDOW_CHARS);
                let key = |edge| key_break(text, marks, edge, &|| *framed);
                let key = key(at.0) || key(at.1);
                if times < 16 && (key || cuts(text, at.0) || cuts(text, at.1)) {
                    return Some(false);
                }
                if key {
                    return None;
                }
                read(text, marks, at, (policy, scan), &mut pieces)
            })
            .find(|read| *read != Some(false));
        if in_secret_table(text, marks, seam) {
            return (WITHHELD.to_string(), vec![(0, WITHHELD.len())]);
        }
        let (run, more) = (run(text, marks, seam), beside(text, marks, seam));
        let (Some(_), Some(run), Some(more)) = (read.flatten(), run, more) else {
            return (WITHHELD.to_string(), vec![(0, WITHHELD.len())]);
        };
        pieces.extend(run.into_iter().map(|at| (at, VALUE_REMOVED)).chain(more));
    }
    rewrite(text, marks, pieces)
}

/// `reach` characters each side of `seam`, out to blanks within `reach` more.
fn window(text: &str, marks: &[Mark], seam: usize, reach: usize) -> Mark {
    let blank = |&(_, ch): &(usize, char)| ch.is_whitespace();
    let mut back = text[..seam].char_indices().rev().skip(reach);
    let from = match back.by_ref().take(reach).find(blank) {
        Some((at, ch)) => at + ch.len_utf8(),
        None => back.next().map_or(0, |(at, ch)| at + ch.len_utf8()),
    };
    let mut on = text[seam..].char_indices().skip(reach);
    let to = match on.by_ref().take(reach).find(blank) {
        Some((at, _)) => seam + at,
        None => on.next().map_or(text.len(), |(at, _)| seam + at),
    };
    let around = |at: usize| marks_in(marks, (at, at)).next().unwrap_or((at, at));
    (around(from).0, around(to).1)
}

/// Whether a window edge at `at` cuts a run of `text` (no blank either side).
fn cuts(text: &str, at: usize) -> bool {
    let blank = char::is_whitespace;
    0 < at && at < text.len() && !text[..at].ends_with(blank) && !text[at..].starts_with(blank)
}

/// Whether `text` has a key frame (`-----BEGIN`, `---- END`, …) or a PuTTY
/// header within 16 KiB ([`MAX_KEY_BYTES`]) each way of `seam`; a bare
/// `----` (a rule) is none.
fn framed(text: &str, seam: usize) -> bool {
    let lo = text.floor_char_boundary(seam.saturating_sub(MAX_KEY_BYTES));
    let hi = text.floor_char_boundary(text.len().min(seam + MAX_KEY_BYTES));
    let signs = ["----BEGIN", "---- BEGIN", "----END", "---- END", "PuTTY-User-Key-File"];
    signs.iter().any(|sign| text[lo..hi].contains(sign))
}

/// Whether a window edge at `at` is a line break inside a key: 16 base64
/// characters or more on each side, and a sign of a key: a frame near the
/// seam (`framed`), a line of 40 base64 characters or more beside the break,
/// a key mark on a line beside it, or a word naming a key on the line above
/// the base64 block, within 16 KiB.
fn key_break(text: &str, marks: &[Mark], at: usize, framed: &dyn Fn() -> bool) -> bool {
    let (Some(back), Some(on)) = (blanks(&text[..at], true), blanks(&text[at..], false)) else {
        return false;
    };
    let (head, tail) = (&text[..at - back], &text[at + on..]);
    let long = |chars: &mut dyn Iterator<Item = char>, len: usize| {
        chars.take(len).filter(|&c| b64(c)).count() == len
    };
    let cut = text[at - back..at + on].contains('\n')
        && long(&mut head.chars().rev(), 16)
        && long(&mut tail.chars(), 16);
    if !cut {
        return false;
    }
    let lo = text.floor_char_boundary(at.saturating_sub(MAX_KEY_BYTES));
    let hi = text.floor_char_boundary(text.len().min(at + MAX_KEY_BYTES));
    let wide = long(&mut head.chars().rev(), 40) || long(&mut tail.chars(), 40);
    let from = text[lo..at - back].rfind('\n').map_or(lo, |i| lo + i);
    let to = text[at + on..hi].find('\n').map_or(hi, |i| at + on + i);
    let secret = |(start, end): Mark| kind(&text[start..end]) == Some(EntityKind::Secret);
    let mut end = at - back;
    let label = loop {
        let start = text[lo..end].rfind('\n').map_or(lo, |i| lo + i + 1);
        let line = text[start..end].trim();
        if start == lo || !(base64(line) && line.len() >= 16) {
            break line.to_lowercase();
        }
        end = start - 1;
    };
    let named = KEY_WORDS.iter().any(|word| label.contains(word));
    wide || named || marks_in(marks, (from, to)).any(secret) || framed()
}

/// Whether `seam` is in a row of a table whose secret column a gate hid
/// before it: a cell delimiter on its line, and a key mark beside one within
/// 16 KiB back. The rows on are out of the reach of the table's header.
fn in_secret_table(text: &str, marks: &[Mark], seam: usize) -> bool {
    const CELLS: [char; 4] = [',', '\t', ';', '|'];
    let lo = text.floor_char_boundary(seam.saturating_sub(MAX_KEY_BYTES));
    let hi = text.floor_char_boundary(text.len().min(seam + MAX_KEY_BYTES));
    let from = text[lo..seam].rfind('\n').map_or(lo, |i| lo + i);
    let to = text[seam..hi].find('\n').map_or(hi, |i| seam + i);
    let cell = |(start, end): Mark| {
        let beside = text[..start].ends_with(CELLS) || text[end..].starts_with(CELLS);
        beside && kind(&text[start..end]) == Some(EntityKind::Secret)
    };
    text[from..to].contains(CELLS) && marks_in(marks, (lo, seam)).any(cell)
}

/// Whether `ch` is a base64 character, and `value` a line of them.
fn b64(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || "+/=".contains(ch)
}
fn base64(value: &str) -> bool {
    !value.is_empty() && value.chars().all(b64)
}

/// Adds to `pieces` the clear bytes of the values in `text[from..to]` that
/// `policy` hides; `Some(false)` when one is at an edge, `None` on a failure.
fn read(
    text: &str,
    marks: &[Mark],
    (from, to): Mark,
    (policy, scan): (GrantPolicy, &dyn Detector),
    pieces: &mut Vec<Piece>,
) -> Option<bool> {
    let (mut view, mut clear, mut at) = (String::new(), Vec::new(), from);
    for (start, end) in marks_in(marks, (from, to)) {
        clear.push((view.len(), at, start - at));
        view.push_str(&text[at..start]);
        push_stand_in(&mut view, &text[start..end]);
        at = end;
    }
    let tokenised = policy == GrantPolicy::Tokenised;
    // The gate's full read: its e-mail layer adds keyword IDs to the residue
    // scan and drops only a public-term name or address (never one with a digit).
    let spans = scan.detect(&view).ok()?;
    if tokenised && view.len() > 1024 && value_too_long(&view) {
        return None; // No secret the gate reads is over 1 KiB.
    }
    let mut hide = Vec::new();
    for span in spans.iter().filter(|span| span_is_well_formed(&view, span)) {
        let first = clear.partition_point(|c| c.0 + c.2 <= span.start);
        // A digest is one in the text too, when the span is in one clear stretch.
        let in_text = clear
            .get(first)
            .filter(|c| c.0 <= span.start && span.end <= c.0 + c.2);
        let in_text = in_text.map(|&(view_at, text_at, _)| Span {
            start: text_at + span.start - view_at,
            end: text_at + span.end - view_at,
            ..*span
        });
        let digest = is_hash_fragment(&view, span)
            && in_text.is_none_or(|span| is_hash_fragment(text, &span));
        if !tokenised && (!span.is_prohibited() || digest) {
            continue;
        }
        let found = hide.len();
        for &(view_at, text_at, len) in clear[first..].iter().take_while(|c| c.0 < span.end) {
            let (start, end) = (span.start.max(view_at), span.end.min(view_at + len));
            let bytes = (text_at + start - view_at, text_at + end - view_at);
            if text[bytes.0..bytes.1].contains(char::is_alphanumeric) {
                hide.push((bytes, removal_text(span.kind).unwrap_or(VALUE_REMOVED)));
            }
        }
        let edge = (span.start == 0 && from > 0) || (span.end == view.len() && to < text.len());
        if edge && hide.len() > found {
            return Some(false);
        }
    }
    pieces.extend(hide);
    Some(true)
}

/// What `mark` reads as: a value that runs on past it (an address after a
/// street, a comma and a short city, as their postcode; a phone as digits a
/// keyword ID can take), or a stand-in and a line end.
fn push_stand_in(view: &mut String, mark: &str) {
    let (_, tail) = view.rsplit_once("1 Main Street, ").unwrap_or_default();
    let city = tail.starts_with(char::is_uppercase) && tail.split_whitespace().nth(3).is_none();
    match kind(mark) {
        _ if mark.is_empty() => {}
        Some(EntityKind::Health) => view.push_str("Cancer"),
        Some(EntityKind::Address) if city => view.push_str("W1A 1AA"),
        Some(EntityKind::Address) => view.push_str("1 Main Street"),
        Some(EntityKind::Secret) => view.push_str("Fake-Pass-42"),
        Some(EntityKind::Phone) => view.push_str("123 4567 82"),
        _ => view.extend([MASKED_STAND_IN, '\n']),
    }
}

/// The class of a mark: its token's kind, or the first one its marker stands for.
fn kind(mark: &str) -> Option<EntityKind> {
    match mark.strip_prefix(PLACEHOLDER_OPEN) {
        Some(token) => kind_of_token(token),
        None => EntityKind::ALL
            .into_iter()
            .find(|&kind| removal_text(kind) == Some(mark)),
    }
}

/// Whether a mark of `kind` is a number often written in groups (`06 12 34`).
fn grouped(kind: EntityKind) -> bool {
    use EntityKind::*;
    let kinds = [
        Phone, Iban, CreditCard, FrNir, FrSiren, FrSiret, FrVat, HuTaj, HuTaxId, ZaId, UkNino,
        NationalId,
    ];
    kinds.contains(&kind)
}

/// The clear text a seam carries on from a key or an address mark beside it
/// (blanks between): the lines of the key, and the words of the address;
/// `None` when a key runs on past [`MAX_KEY_BYTES`].
fn beside(text: &str, marks: &[Mark], seam: usize) -> Option<Vec<Piece>> {
    let before = blanks(&text[..seam], true).map(|len| seam - len);
    let after = blanks(&text[seam..], false).map(|len| seam + len);
    let glued = before == Some(seam) && after == Some(seam);
    let mut pieces = Vec::new();
    for (back, edge) in [(false, before), (true, after)] {
        let Some(edge) = edge else { continue };
        let Ok(at) = marks.binary_search_by_key(&edge, |m| if back { m.0 } else { m.1 }) else {
            continue;
        };
        let (start, end) = marks[at];
        let (found, kind) = match kind(&text[start..end]) {
            Some(kind @ EntityKind::Secret) => (key_lines(text, marks, seam, back, glued)?, kind),
            Some(kind @ EntityKind::Address) => (address_words(text, marks, seam, back), kind),
            _ => continue,
        };
        let marker = removal_text(kind).unwrap_or(VALUE_REMOVED);
        pieces.extend(found.into_iter().map(|at| (at, marker)));
    }
    Some(pieces)
}

/// The lines of a key that run on from its mark across `seam`, going `back`
/// or on: the rest of a glued line, then each line of base64 (16 characters
/// or more, or padded) or of marks, and a short last one, up to and with a
/// `----` frame (or the cut end of one); `None` for a short line inside the
/// key or past [`MAX_KEY_BYTES`].
fn key_lines(text: &str, marks: &[Mark], seam: usize, back: bool, glued: bool) -> Option<Marks> {
    let line_at = |at: usize| {
        let line = match back {
            true => {
                let lo = text.floor_char_boundary(at.saturating_sub(MAX_KEY_BYTES));
                (text[lo..at].rfind('\n').map_or(lo, |i| lo + i + 1), at)
            }
            false => {
                let hi = text.floor_char_boundary(text.len().min(at + MAX_KEY_BYTES));
                (at, text[at..hi].find('\n').map_or(hi, |i| at + i))
            }
        };
        let (mut clear, mut parts, mut from) = (String::new(), Vec::new(), line.0);
        for (start, end) in marks_in(marks, line) {
            clear.push_str(&text[from..start]);
            parts.push((from, start));
            from = end;
        }
        (if back { line.0 } else { line.1 }, parts, clear)
    };
    let frame = |value: &str| value.starts_with("----") || value.ends_with("----");
    let long = |value: &str| base64(value) && (value.len() >= 16 || value.ends_with('='));
    let (mut lines, mut at, mut body, mut fresh) = (Vec::new(), seam, false, true);
    loop {
        let (far, parts, clear) = line_at(at);
        let (value, first, marked) = (clear.trim(), at == seam, parts.len() > 1);
        let edge = far == if back { 0 } else { text.len() };
        let bounded = !edge && text.as_bytes()[if back { far - 1 } else { far }] != b'\n';
        let next = (!edge && !bounded).then(|| line_at(if back { far - 1 } else { far + 1 }).2);
        let next = next.as_deref().map(str::trim);
        // A short line ends the key: before a frame, after a body line, or
        // as the first line with text on from the key's mark (its cut-off last line).
        let short = base64(value) && !long(value);
        let cut_off = fresh && !back && !glued;
        if short && (body || cut_off) && next.is_some_and(long) {
            return None;
        }
        let short = short && (body || cut_off || next.is_some_and(frame));
        let empty = value.is_empty() && (first || marked);
        if !(frame(value) || long(value) || short || empty || (first && glued)) {
            break;
        }
        if bounded || at.abs_diff(seam) > MAX_KEY_BYTES {
            return None;
        }
        body |= long(value) || marked || (first && glued);
        fresh &= value.is_empty();
        lines.extend(parts);
        if frame(value) || edge {
            break;
        }
        at = if back { far - 1 } else { far + 1 };
    }
    Some(lines)
}

/// The words of an address that run on from its mark across `seam`, going
/// `back` or on, at most [`MAX_ADDRESS_WORDS`], to a sentence end, a blank line
/// or a mark: those up to a number, a street word or an address mark, a city
/// after a number and a city ([`CITIES`], or a public term). Other
/// capitalised words are prose.
fn address_words(text: &str, marks: &[Mark], seam: usize, back: bool) -> Marks {
    const STREET: &str = "rue avenue boulevard bd place chemin allée impasse quai route \
        street road lane";
    const LINK: &str = "de la le les du des";
    let (mut taken, mut words, mut at, mut number) = (None, None::<Mark>, seam, false);
    for _ in 0..MAX_ADDRESS_WORDS {
        let rest = if back { &text[..at] } else { &text[at..] };
        let Some(gap) = blanks(rest, back) else { break };
        let trimmed = if back {
            &rest[..rest.len() - gap]
        } else {
            &rest[gap..]
        };
        let word = match back {
            true => {
                let lo = trimmed.floor_char_boundary(trimmed.len().saturating_sub(MAX_BLANKS));
                match trimmed[lo..]
                    .char_indices()
                    .rfind(|&(_, ch)| ch.is_whitespace())
                {
                    Some((i, ch)) => (lo + i + ch.len_utf8(), trimmed.len()),
                    None if lo == 0 => (0, trimmed.len()),
                    None => break,
                }
            }
            false => {
                let hi = trimmed.floor_char_boundary(trimmed.len().min(MAX_BLANKS));
                match trimmed[..hi].find(char::is_whitespace) {
                    Some(i) => (at + gap, at + gap + i),
                    None if hi == trimmed.len() => (at + gap, at + gap + trimmed.len()),
                    None => break,
                }
            }
        };
        let blanks = if back { (word.1, at) } else { (at, word.0) };
        let mark = marks_in(marks, word).find(|(from, to)| from < to);
        if let Some((from, to)) = mark {
            if kind(&text[from..to]) == Some(EntityKind::Address) {
                taken = words;
            }
            break;
        }
        let value = &text[word.0..word.1];
        let bare = value.trim_matches(|ch: char| ",.;:!?()".contains(ch));
        let ends = value.ends_with(['.', ';', ':', '!', '?']);
        let lower = bare.to_lowercase();
        let street = STREET.split_whitespace().any(|word| word == lower);
        let digits = bare.contains(|ch: char| ch.is_ascii_digit());
        let capital = bare.starts_with(char::is_uppercase);
        let link = bare.is_empty() || LINK.split_whitespace().any(|word| word == lower);
        let stop = word.0 == word.1
            || text[blanks.0..blanks.1].matches('\n').count() > 1
            || (back && ends);
        if stop || !(street || digits || capital || link) {
            break;
        }
        words = Some(words.map_or(word, |(from, to)| (from.min(word.0), to.max(word.1))));
        let city = PUBLIC.contains(bare) || CITY_FOLDS.contains(&fold(bare));
        if street || digits || (capital && number && !back) || city {
            taken = words;
        }
        (at, number) = (if back { word.0 } else { word.1 }, digits);
        if ends {
            break;
        }
    }
    taken.into_iter().collect()
}

/// The clear text a seam ties to a mark: the word glued across it and the
/// number in groups through it (`⟦IBAN_…⟧ 3456`), each when it holds one.
fn run(text: &str, marks: &[Mark], seam: usize) -> Option<Marks> {
    let glued = !text[..seam].ends_with(char::is_whitespace)
        && !text[seam..].starts_with(char::is_whitespace);
    let mut pieces = Vec::new();
    for number in [glued.then_some(false), Some(true)].into_iter().flatten() {
        let (start, cut) = walk(text, marks, seam, (true, number));
        let (end, cap) = walk(text, marks, seam, (false, number));
        if marks_in(marks, (start, end)).all(|(from, to)| from == to) {
            continue;
        }
        if cut || cap {
            return None;
        }
        let mut at = start;
        for (from, to) in marks_in(marks, (start, end)) {
            pieces.push((at, from));
            at = to;
        }
    }
    Some(pieces)
}

/// Where the word through `seam` ends, going `back` or on, or the `number`
/// (digits, capitals, `+-./`, lone spaces, number marks), and if it was cut.
fn walk(text: &str, marks: &[Mark], seam: usize, (back, number): (bool, bool)) -> (usize, bool) {
    let step = |at: usize| match back {
        true => text[..at].chars().next_back(),
        false => text[at..].chars().next(),
    };
    let joins = |ch: char, at: usize| match number {
        false => !ch.is_whitespace() && !"[]⟦⟧".contains(ch),
        true => {
            let lone = ch == ' ' && step(if back { at - 1 } else { at + 1 }) != Some(' ');
            lone || ch.is_ascii_digit() || ch.is_ascii_uppercase() || "+-./".contains(ch)
        }
    };
    let mut at = seam;
    loop {
        if let Ok(next) = marks.binary_search_by_key(&at, |m| if back { m.1 } else { m.0 }) {
            let (start, end) = marks[next];
            if number && !kind(&text[start..end]).is_some_and(grouped) {
                return (at, false);
            }
            at = if back { start } else { end };
        } else if let Some(ch) = step(at).filter(|&ch| joins(ch, at)) {
            if at.abs_diff(seam) >= MAX_RUN_BYTES {
                return (at, true);
            }
            let len = ch.len_utf8();
            at = if back { at - len } else { at + len };
        } else {
            return (at, false);
        }
    }
}

/// The marks in `from..to`, then an empty one at `to`.
fn marks_in(marks: &[Mark], (from, to): Mark) -> impl Iterator<Item = Mark> + '_ {
    let first = marks.partition_point(|m| m.1 <= from);
    let inner = marks[first..].iter().take_while(move |m| m.0 < to);
    inner.copied().chain(once((to, to)))
}

/// `text` with each trimmed piece that holds a letter or digit replaced by its
/// marker (an overlap writes its tail), and the marks moved, plus one for each marker.
fn rewrite(text: &str, marks: &[Mark], mut pieces: Vec<Piece>) -> (String, Marks) {
    pieces.sort_unstable();
    let (mut out, mut kept) = (String::with_capacity(text.len()), Vec::new());
    let (mut from, mut next) = (0, 0);
    for ((start, end), marker) in pieces.into_iter().chain([((text.len(), text.len()), "")]) {
        if start < from && end <= from {
            continue;
        }
        let start = start.max(from);
        let piece = &text[start..end];
        let start = start + piece.len() - piece.trim_start().len();
        let end = start + piece.trim().len();
        if start < end && !text[start..end].contains(char::is_alphanumeric) {
            continue;
        }
        let base = out.len();
        while next < marks.len() && marks[next].1 <= start {
            kept.push((base + marks[next].0 - from, base + marks[next].1 - from));
            next += 1;
        }
        out.push_str(&text[from..start]);
        if start < end {
            kept.push((out.len(), out.len() + marker.len()));
            out.push_str(marker);
        }
        from = end;
    }
    (out, kept)
}

#[cfg(test)]
mod tests {
    use super::super::detector::{without_names, StandardDetector};
    use super::{mend, rewrite, GrantPolicy};

    /// Open shows a digest, judged on the text too: a hex run after a key
    /// marker is 30 characters there, though the key's stand-in (`…42`) makes
    /// it 32 in the read.
    #[test]
    fn a_digest_is_one_in_the_text_too() {
        let text = "x [secret removed]DE00ABCDEF0123456789ABCDEF0123 ok";
        let seam = text.find(" ok").expect("seam");
        let scan = without_names(StandardDetector::new());
        let open = GrantPolicy::Passthrough;
        let (out, _) = mend(text, &[(2, 18)], &[seam], open, scan.as_ref());
        assert!(!out.contains("ABCDEF0123456789"), "{out}");
    }

    /// A piece that overlaps one already written writes its tail: no byte vanishes.
    #[test]
    fn an_overlapping_piece_writes_its_tail() {
        let pieces = vec![((0, 5), "[a]"), ((3, 8), "[b]"), ((4, 6), "[c]")];
        let (out, marks) = rewrite("abcdefghij", &[(9, 10)], pieces);
        assert_eq!(out, "[a][b]ij");
        assert_eq!(marks, vec![(0, 3), (3, 6), (7, 8)]);
    }
}
