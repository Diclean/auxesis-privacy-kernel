//! The seams of [`SafeText::join`](super::SafeText::join), each read again by
//! the private recognisers with the tokens and markers the kernel wrote (its
//! marks) as fixed stand-ins, never edited. A value found that the mode hides,
//! or clear text a seam ties to a mark (a glued word, a number in groups, the
//! lines of a key, the words of an address), becomes a fixed marker.

use std::iter::once;

use kernel_core::privacy::GrantPolicy;

use super::detector::Detector;
use super::prohibited::{is_hash_fragment, removal_text};
use super::residue::MASKED_STAND_IN;
use super::tokens::session_token_len;
use crate::anonymize::{kind_of_token, PLACEHOLDER_OPEN};
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

/// The join of `text`, read again 4, then 16 times wider when a value or the
/// window cuts a run at its edge, or [`WITHHELD`].
pub(super) fn mend(
    text: &str,
    marks: &[Mark],
    seams: &[usize],
    policy: GrantPolicy,
    scan: &dyn Detector,
) -> (String, Marks) {
    let mut pieces = Vec::new();
    for &seam in seams {
        let read = [1, 4, 16]
            .into_iter()
            .map(|times| {
                let at = window(text, marks, seam, times * WINDOW_CHARS);
                if times < 16 && (cuts(text, at.0) || cuts(text, at.1)) {
                    return Some(false);
                }
                read(text, marks, at, (policy, scan), &mut pieces)
            })
            .find(|read| *read != Some(false));
        match (
            read.flatten(),
            run(text, marks, seam),
            beside(text, marks, seam),
        ) {
            (Some(_), Some(run), Some(more)) => {
                pieces.extend(run.into_iter().map(|at| (at, VALUE_REMOVED)));
                pieces.extend(more);
            }
            _ => return (WITHHELD.to_string(), vec![(0, WITHHELD.len())]),
        }
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
    let before = text[..seam].trim_end().len();
    let after = text.len() - text[seam..].trim_start().len();
    let glued = before == seam && after == seam;
    let mut pieces = Vec::new();
    for (back, edge) in [(false, before), (true, after)] {
        let Ok(at) = marks.binary_search_by_key(&edge, |m| if back { m.0 } else { m.1 }) else {
            continue;
        };
        let (start, end) = marks[at];
        match kind(&text[start..end]) {
            Some(EntityKind::Secret) => pieces.extend(key_lines(text, marks, seam, back, glued)?),
            Some(EntityKind::Address) => pieces.extend(address_words(text, marks, seam, back)),
            _ => {}
        }
    }
    Some(pieces)
}

/// The lines of a key that run on from its mark across `seam`, going `back`
/// or on: the rest of a glued line, then each line of base64 (16 characters
/// or more, or padded) or of marks, up to and with a `----` frame (or the cut
/// end of one); `None` past [`MAX_KEY_BYTES`].
fn key_lines(
    text: &str,
    marks: &[Mark],
    seam: usize,
    back: bool,
    glued: bool,
) -> Option<Vec<Piece>> {
    let base64 = |ch: char| ch.is_ascii_alphanumeric() || "+/=".contains(ch);
    let (mut lines, mut at) = (Vec::new(), seam);
    loop {
        let line = match back {
            true => (text[..at].rfind('\n').map_or(0, |i| i + 1), at),
            false => (at, text[at..].find('\n').map_or(text.len(), |i| at + i)),
        };
        let (mut clear, mut parts, mut from) = (String::new(), Vec::new(), line.0);
        for (start, end) in marks_in(marks, line) {
            clear.push_str(&text[from..start]);
            parts.push((from, start));
            from = end;
        }
        let value = clear.trim();
        let frame = value.starts_with("----") || value.ends_with("----");
        let body = (value.len() >= 16 || value.ends_with('=')) && value.chars().all(base64);
        let (first, marked) = (at == seam, parts.len() > 1);
        if !(frame || body || (value.is_empty() && (first || marked)) || (first && glued)) {
            break;
        }
        if at.abs_diff(seam) > MAX_KEY_BYTES {
            return None;
        }
        lines.extend(parts);
        if frame || (back && line.0 == 0) || (!back && line.1 == text.len()) {
            break;
        }
        at = if back { line.0 - 1 } else { line.1 + 1 };
    }
    let marker = removal_text(EntityKind::Secret).unwrap_or(VALUE_REMOVED);
    Some(lines.into_iter().map(|at| (at, marker)).collect())
}

/// The words of an address that run on from its mark across `seam`, going
/// `back` or on: capitalised, numbers, punctuation and street words, at most
/// [`MAX_ADDRESS_WORDS`], to a sentence end, a blank line or another mark.
fn address_words(text: &str, marks: &[Mark], seam: usize, back: bool) -> Vec<Piece> {
    const STREET: &str = "de la le les du des rue avenue boulevard bd place chemin allée \
        impasse quai route street road";
    let (mut words, mut at) = (None::<Mark>, seam);
    for _ in 0..MAX_ADDRESS_WORDS {
        let rest = if back { &text[..at] } else { &text[at..] };
        let trimmed = if back {
            rest.trim_end()
        } else {
            rest.trim_start()
        };
        let gap = &rest[if back { trimmed.len() } else { 0 }..][..rest.len() - trimmed.len()];
        let word = match back {
            true => {
                let blank = trimmed.char_indices().rfind(|&(_, ch)| ch.is_whitespace());
                (blank.map_or(0, |(i, ch)| i + ch.len_utf8()), trimmed.len())
            }
            false => {
                let start = at + gap.len();
                (
                    start,
                    start + trimmed.find(char::is_whitespace).unwrap_or(trimmed.len()),
                )
            }
        };
        let value = &text[word.0..word.1];
        let bare = value.trim_matches(|ch: char| ",.;:!?()".contains(ch));
        let ends = value.ends_with(['.', ';', ':', '!', '?']);
        let address = bare.is_empty()
            || bare.starts_with(|ch: char| ch.is_uppercase() || ch.is_ascii_digit())
            || STREET
                .split_whitespace()
                .any(|word| word == bare.to_lowercase());
        let marked = marks_in(marks, word).any(|(from, to)| from < to);
        if word.0 == word.1 || gap.matches('\n').count() > 1 || marked || !address || (back && ends)
        {
            break;
        }
        words = Some(words.map_or(word, |(from, to)| (from.min(word.0), to.max(word.1))));
        at = if back { word.0 } else { word.1 };
        if ends {
            break;
        }
    }
    let marker = removal_text(EntityKind::Address).unwrap_or(VALUE_REMOVED);
    words.into_iter().map(|at| (at, marker)).collect()
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
    let lower = |ch: Option<char>| ch.is_some_and(char::is_lowercase);
    let joins = |ch: char, at: usize| match number {
        false => !ch.is_whitespace() && !"[]⟦⟧".contains(ch),
        true => {
            let lone = ch == ' ' && step(if back { at - 1 } else { at + 1 }) != Some(' ');
            // A capital beside a lower-case letter is a word (`The`), not a group.
            let capital = ch.is_ascii_uppercase() && {
                let (start, end) = if back { (at - 1, at) } else { (at, at + 1) };
                !lower(text[..start].chars().next_back()) && !lower(text[end..].chars().next())
            };
            lone || ch.is_ascii_digit() || capital || "+-./".contains(ch)
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
/// marker (a piece that overlaps one written writes its tail), and the marks
/// moved, plus one for each marker.
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
    use super::rewrite;

    /// A piece that overlaps one already written writes its tail: no byte vanishes.
    #[test]
    fn an_overlapping_piece_writes_its_tail() {
        let pieces = vec![((0, 5), "[a]"), ((3, 8), "[b]"), ((4, 6), "[c]")];
        let (out, marks) = rewrite("abcdefghij", &[(9, 10)], pieces);
        assert_eq!(out, "[a][b]ij");
        assert_eq!(marks, vec![(0, 3), (3, 6), (7, 8)]);
    }
}
