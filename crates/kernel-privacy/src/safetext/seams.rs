//! The seams of [`SafeText::join`](super::SafeText::join), each read again by
//! the private recognisers with the tokens and markers the kernel wrote (its
//! marks) as fixed stand-ins, never edited. A value found that the mode hides,
//! or clear text a seam ties to a mark, becomes a fixed marker.

use std::iter::once;

use kernel_core::privacy::GrantPolicy;

use super::detector::Detector;
use super::prohibited::{is_hash_fragment, removal_text};
use super::residue::MASKED_STAND_IN;
use super::tokens::session_token_len;
use crate::anonymize::{kind_of_token, PLACEHOLDER_OPEN};
use crate::recognizer::span_is_well_formed;
use crate::recognizers::secrets::value_too_long;
use crate::span::EntityKind;

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
        let read = [1, 4, 16]
            .into_iter()
            .map(|times| {
                let at = window(text, marks, seam, times * WINDOW_CHARS);
                read(text, marks, at, (policy, scan), &mut pieces)
            })
            .find(|read| *read != Some(false));
        match (read.flatten(), run(text, marks, seam)) {
            (Some(_), Some(run)) => pieces.extend(run.into_iter().map(|at| (at, VALUE_REMOVED))),
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
    let spans = scan.residue(&view).ok()?; // No secret the gate reads is over 1 KiB.
    if tokenised && view.len() > 1024 && value_too_long(&view) {
        return None;
    }
    let mut hide = Vec::new();
    for span in spans.iter().filter(|span| span_is_well_formed(&view, span)) {
        if !tokenised && (!span.is_prohibited() || is_hash_fragment(&view, span)) {
            continue;
        }
        let found = hide.len();
        let first = clear.partition_point(|c| c.0 + c.2 <= span.start);
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
/// street, a comma and a short city, as their postcode), or a stand-in and a line end.
fn push_stand_in(view: &mut String, mark: &str) {
    let (_, tail) = view.rsplit_once("1 Main Street, ").unwrap_or_default();
    let city = tail.starts_with(char::is_uppercase) && tail.split_whitespace().nth(3).is_none();
    match kind(mark) {
        _ if mark.is_empty() => {}
        Some(EntityKind::Health) => view.push_str("Cancer"),
        Some(EntityKind::Address) if city => view.push_str("W1A 1AA"),
        Some(EntityKind::Address) => view.push_str("1 Main Street"),
        Some(EntityKind::Secret) => view.push_str("Fake-Pass-42"),
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
/// marker (overlaps merge), and the marks moved, plus one for each marker.
fn rewrite(text: &str, marks: &[Mark], mut pieces: Vec<Piece>) -> (String, Marks) {
    pieces.sort_unstable();
    let (mut out, mut kept) = (String::with_capacity(text.len()), Vec::new());
    let (mut from, mut next) = (0, 0);
    for ((start, end), marker) in pieces.into_iter().chain([((text.len(), text.len()), "")]) {
        let piece = &text[start..end];
        let start = start + piece.len() - piece.trim_start().len();
        let end = start + piece.trim().len();
        if start < end && !text[start..end].contains(char::is_alphanumeric) {
            continue;
        }
        if start < from {
            from = from.max(end);
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
