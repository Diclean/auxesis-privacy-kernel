//! The seams of a join: a value that shows only where two parts meet.
//!
//! Each part of [`SafeText::join`](super::SafeText::join) passed a gate on its
//! own, so a value cut between two parts was never read whole: half an IBAN in
//! each, a label in one and its secret in the next, an ID over two lines. The
//! join reads the joined text again with the Standard recognisers, names off:
//! the detector of every private gate.
//!
//! It reads the whole text, not a window around each seam. No window bound
//! holds for every recogniser: a table's header line names the column of
//! every row below it, and a quoted record runs on to the line that closes it,
//! however far.
//!
//! What it reads:
//! * three views of the text: as joined, with each blank run that touches a
//!   seam and holds at most one line end deleted, and with that run as one
//!   space. A value cut by a space or a line break between two parts then reads
//!   whole, and a paragraph break stays one;
//! * a token or a removal marker a part carries reads the way the gate's
//!   residue scan reads a token: a stand-in, then a line end;
//! * a span that one part shows on its own was read there by that part's gate,
//!   and stays as that part issued it;
//! * a value a part already masked in part: see `cut_values`.
//!
//! What it writes: every other span is replaced with a fixed marker, the one
//! open mode writes for its class, or [`VALUE_REMOVED`]. The join holds no
//! session key to tokenise the value and no grant to read the mode, so it
//! treats the value as one that never leaves. No byte of a token, a marker or
//! a literal `⟦` is ever rewritten, so every part's tokens restore as before.

use crate::anonymize::PLACEHOLDER_OPEN;
use crate::recognizer::Recognizer;
use crate::recognizers::secrets::value_too_long;
use crate::recognizers::sensitive_terms::{in_word, phrase_word, SensitiveTermsRecognizer};
use crate::span::{EntityKind, Span};

use super::detector::{without_names, StandardDetector, PRIVATE_DETECTOR};
use super::prohibited::{export_spans, is_hash_fragment, removal_text};
use super::residue::MASKED_STAND_IN;
use super::tokens::session_token_len;

/// The marker for a value of a class that has no removal marker of its own (an
/// e-mail address, a phone number, a URL).
pub(super) const VALUE_REMOVED: &str = "[value removed]";

/// The text a join issues when its seams cannot be read: nothing of its parts.
pub(super) const WITHHELD: &str = "[auxesis: withheld]";

/// How many items the chain around a seam reads on each side: more than the
/// groups of the longest value (an IBAN of 34 characters, in groups of four).
const REACH: usize = 12;

/// The longest word a chain reads, in characters: a longer word ends it.
const LONGEST_WORD: usize = 512;

/// The characters a value is grouped with inside a part.
const JOINTS: [char; 6] = [' ', '-', '.', '/', '\'', '\u{a0}'];

/// A byte range of the joined text the join never rewrites, and whether the
/// view reads it as a stand-in (a token, a marker) or as itself (a literal `⟦`).
type Kept = (usize, usize, bool);

/// A byte range the join masks, with the class whose marker it takes (`None`:
/// [`VALUE_REMOVED`]).
type Mask = (usize, usize, Option<EntityKind>);

/// `parts` joined, with every value only a seam shows replaced by its marker;
/// `None` when the joined text cannot be read, so nothing of it may leave.
pub(super) fn join(parts: &[String]) -> Option<String> {
    let joined = parts.concat();
    let mut at = 0;
    let bounds: Vec<(usize, usize)> = parts
        .iter()
        .filter_map(|part| {
            at += part.len();
            (!part.is_empty()).then_some((at - part.len(), at))
        })
        .collect();
    if bounds.len() < 2 {
        return Some(joined);
    }
    let kept: Vec<Kept> = bounds
        .iter()
        .flat_map(|&part| kept_ranges(&joined, part))
        .collect();
    let view = stand_in_view(&joined, &kept);
    let detector = PRIVATE_DETECTOR.get_or_init(|| without_names(StandardDetector::new()));
    let read = |text: &str| -> Option<Vec<Span>> {
        let found = detector.detect(text).ok()?;
        Some(found.into_iter().chain(export_spans(text)).collect())
    };
    let runs = seam_runs(&joined, &bounds);
    // A view whose every run is already written as `with` is the joined text.
    let rewrites = |with: &str| runs.iter().any(|&(start, end)| &joined[start..end] != with);
    let mut spans = Vec::new();
    for with in [None, Some(""), Some(" ")] {
        let (text, moved) = match with {
            None => (view.clone(), Vec::new()),
            Some(with) if rewrites(with) => rewrite(&view, &runs, with),
            Some(_) => continue,
        };
        // A secret past the read cap in any view, whichever part holds it:
        // refused, like the gate refuses one, never masked in part.
        if value_too_long(&text) {
            return None;
        }
        let width = with.map_or(0, str::len);
        for span in read(&text)? {
            let start = back(&moved, width, span.start, false);
            let end = back(&moved, width, span.end, true);
            spans.push(Span { start, end, ..span });
        }
    }
    let mut alone: Vec<Option<Vec<Span>>> = vec![None; bounds.len()];
    let mut masks = Vec::new();
    for span in spans {
        if span.start >= span.end || is_hash_fragment(&joined, &span) {
            continue;
        }
        // A span its part shows on its own stays as that part issued it.
        let index = bounds.partition_point(|&(_, end)| end <= span.start);
        let inside = |part: &&(usize, usize)| part.0 <= span.start && span.end <= part.1;
        if let Some(&(start, end)) = bounds.get(index).filter(inside) {
            if alone[index].is_none() {
                alone[index] = Some(read(&view[start..end])?);
            }
            let (from, to) = (span.start - start, span.end - start);
            let shown = |own: &Span| own.kind == span.kind && own.start <= from && to <= own.end;
            if alone[index].iter().flatten().any(shown) {
                continue;
            }
        }
        clip(&kept, (span.start, span.end), Some(span.kind), &mut masks);
    }
    cut_values(&joined, &bounds, &kept, &runs, &mut masks)?;
    write_markers(&joined, masks)
}

/// The kept ranges of the part at `start..end` of `joined`: a token (read the
/// way restore reads one, so `⟦⟦` is a literal opener) and a removal marker read
/// as stand-ins; a literal `⟦` reads as itself.
fn kept_ranges(joined: &str, (start, end): (usize, usize)) -> Vec<Kept> {
    let open = PLACEHOLDER_OPEN.len_utf8();
    let marker = |rest: &str| {
        let markers = EntityKind::ALL.into_iter().filter_map(removal_text);
        markers
            .chain([VALUE_REMOVED, WITHHELD])
            .find(|text| rest.starts_with(text))
    };
    let (mut kept, mut at) = (Vec::new(), start);
    while let Some(offset) = joined[at..end].find([PLACEHOLDER_OPEN, '[']) {
        let from = at + offset;
        let rest = &joined[from..end];
        let (len, stand_in) = match marker(rest) {
            Some(marker) => (marker.len(), true),
            None if rest.starts_with('[') => (1, false),
            None if rest[open..].starts_with(PLACEHOLDER_OPEN) => (2 * open, false),
            None => session_token_len(rest).map_or((open, false), |len| (len, true)),
        };
        if stand_in || !rest.starts_with('[') {
            kept.push((from, from + len, stand_in));
        }
        at = from + len;
    }
    kept
}

/// `joined` with each stand-in range of `kept` written as the gate's residue
/// scan reads a token: the stand-in, blanks, then a line end. The byte length is
/// unchanged, so an offset in the view is the same offset in `joined`.
fn stand_in_view(joined: &str, kept: &[Kept]) -> String {
    let (mut view, mut from) = (String::with_capacity(joined.len()), 0);
    let stand_in = MASKED_STAND_IN.len_utf8();
    for &(start, end, _) in kept
        .iter()
        .filter(|kept| kept.2 && kept.1 - kept.0 > stand_in)
    {
        view.push_str(&joined[from..start]);
        view.push(MASKED_STAND_IN);
        view.extend(std::iter::repeat_n(' ', end - start - stand_in - 1));
        view.push('\n');
        from = end;
    }
    view.push_str(&joined[from..]);
    view
}

/// The maximal blank runs of `joined` that touch a seam (the start of each
/// part after the first) and hold at most one line end, sorted and disjoint.
/// Each byte is read at most three times.
fn seam_runs(joined: &str, bounds: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for &(seam, _) in &bounds[1..] {
        // A seam inside the last run is in that run.
        let reach = runs.last().map_or(0, |run| run.1);
        if seam < reach {
            continue;
        }
        let start = reach + joined[reach..seam].trim_end().len();
        let end = seam + joined[seam..].len() - joined[seam..].trim_start().len();
        if start < end {
            runs.push((start, end));
        }
    }
    runs.retain(|&(start, end)| joined[start..end].matches('\n').count() < 2);
    runs
}

/// `view` with each run of `runs` written as `with`, and where each run went:
/// its offset in the new text, then its range in the view.
fn rewrite(
    view: &str,
    runs: &[(usize, usize)],
    with: &str,
) -> (String, Vec<(usize, usize, usize)>) {
    let (mut text, mut moved, mut from) = (String::with_capacity(view.len()), Vec::new(), 0);
    for &(start, end) in runs {
        text.push_str(&view[from..start]);
        moved.push((text.len(), start, end));
        text.push_str(with);
        from = end;
    }
    text.push_str(&view[from..]);
    (text, moved)
}

/// The view offset of `offset` in a text [`rewrite`] wrote with runs `width`
/// bytes long. A start inside a rewritten run takes the whole run, so a range
/// only widens.
fn back(moved: &[(usize, usize, usize)], width: usize, offset: usize, ending: bool) -> usize {
    let index = moved.partition_point(|&(new, _, _)| new < offset || (!ending && new == offset));
    match index.checked_sub(1).map(|index| moved[index]) {
        None => offset,
        Some((new, start, _)) if offset < new + width => start,
        Some((new, _, end)) => end + (offset - new - width),
    }
}

/// A word, or a mask a part carries, in the chain around a seam.
#[derive(Clone, Copy)]
struct Item {
    start: usize,
    end: usize,
    mask: bool,
    /// The class of a mask; `None` for a word, or a marker of no class.
    kind: Option<EntityKind>,
}

/// Mask the words around each seam that go on with a value a part already
/// masked, with the class of that mask.
///
/// A part may have masked a piece of a value the seam cut: its own gate read
/// that piece, not the value. The rest is then in clear beside the mask, and
/// the recognisers cannot read the whole, because the join holds no key to
/// read what the mask hides. The chain around a seam is the masks and words in
/// a row on each side of it, one joint character apart or glued to a mask, and
/// across the seam's blank run when that holds at most one line end. A word
/// joins the chain while it can be a piece of a value: it has a digit, or all
/// its letters are capitals; it is glued at the seam to a mask of a class
/// written in words (a secret, a health term), so the rest of a word the seam
/// cut; or, past a mask of a lexicon class, it is a word of a multi-word term
/// (at the seam, the word before one counts too: the rest of its first word).
/// The two words at a seam read as one word, since the seam may cut one. When
/// the chain crosses the seam and holds a mask, it is masked from its first
/// item to its last, all but its masks. `None` when such a chain runs into a
/// word too long to read: the value may go on in it, so nothing of the join
/// may leave.
fn cut_values(
    joined: &str,
    bounds: &[(usize, usize)],
    kept: &[Kept],
    runs: &[(usize, usize)],
    masks: &mut Vec<Mask>,
) -> Option<()> {
    let terms = SensitiveTermsRecognizer::new();
    let term = |item: &Item| item.kind.is_some_and(|kind| terms.kinds().contains(&kind));
    let text = |item: &Item| &joined[item.start..item.end];
    let shaped =
        |word: &str| word.chars().any(char::is_numeric) || word.chars().all(char::is_uppercase);
    let goes_on = |word: &str, mask: Option<&Item>, later| {
        shaped(word) || mask.is_some_and(|mask| term(mask) && phrase_word(word, later))
    };
    let (mut gaps, mut last) = (runs.iter().peekable(), None);
    for &(seam, _) in &bounds[1..] {
        while gaps.next_if(|run| run.1 < seam).is_some() {}
        let gap = gaps
            .peek()
            .filter(|run| run.0 <= seam)
            .map_or((seam, seam), |run| **run);
        if last.replace(gap) == Some(gap) {
            continue;
        }
        let sides = [
            items(joined, kept, gap.0, false),
            items(joined, kept, gap.1, true),
        ];
        let (Some(&left), Some(&right)) = (sides[0].0.first(), sides[1].0.first()) else {
            let beside = sides
                .iter()
                .any(|(side, _)| side.first().is_some_and(|item| item.mask));
            if beside && sides.iter().any(|(side, long)| side.is_empty() && *long) {
                return None;
            }
            continue;
        };
        let crosses = match (left.mask, right.mask) {
            (true, true) => true,
            (false, false) => {
                let word = format!("{}{}", text(&left), text(&right));
                goes_on(&word, sides[0].0.get(1), true) || goes_on(&word, sides[1].0.get(1), false)
            }
            _ => {
                let (mask, side, later) = match left.mask {
                    true => (left, &sides[1].0, true),
                    false => (right, &sides[0].0, false),
                };
                let mut words = side.iter().take(2).filter(|item| !item.mask);
                shaped(text(&side[0]))
                    || (gap.0 == gap.1 && (term(&mask) || mask.kind == Some(EntityKind::Secret)))
                    || (term(&mask) && words.any(|word| phrase_word(text(word), later)))
            }
        };
        if !crosses {
            continue;
        }
        let mut chain = vec![left, right];
        let mut runs_on = false;
        for ((side, long), other, later) in [(&sides[0], right, false), (&sides[1], left, true)] {
            // The mask nearest the seam: past a lexicon mask, a term goes on.
            let mut near = [side[0], other].into_iter().find(|item| item.mask);
            let before = chain.len();
            chain.extend(side[1..].iter().take_while(|item| {
                near = if item.mask { Some(**item) } else { near };
                item.mask || goes_on(text(item), near.as_ref(), later)
            }));
            runs_on |= *long && chain.len() - before == side.len() - 1;
        }
        if !chain.iter().any(|item| item.mask) {
            continue;
        }
        if runs_on {
            return None;
        }
        let kind = chain
            .iter()
            .filter_map(|item| item.kind)
            .min_by_key(|kind| kind.mask_priority());
        let start = chain.iter().map(|item| item.start).min()?;
        let end = chain.iter().map(|item| item.end).max()?;
        if chain.iter().any(|item| !item.mask) {
            clip(kept, (start, end), kind, masks);
        }
    }
    Some(())
}

/// Up to [`REACH`] items in a row from `at`, going `ahead` or back: masks and
/// words, each one joint character from the next, or glued to a mask; and
/// whether the row stops at a word longer than [`LONGEST_WORD`].
fn items(joined: &str, kept: &[Kept], mut at: usize, ahead: bool) -> (Vec<Item>, bool) {
    let next = |at: usize| match ahead {
        true => joined[at..].chars().next(),
        false => joined[..at].chars().next_back(),
    };
    let step = |at: usize, ch: char| {
        if ahead {
            at + ch.len_utf8()
        } else {
            at - ch.len_utf8()
        }
    };
    let mut found = Vec::new();
    while found.len() < REACH {
        let index = kept.partition_point(|kept| if ahead { kept.0 < at } else { kept.1 < at });
        let edge = |kept: &&Kept| kept.2 && at == if ahead { kept.0 } else { kept.1 };
        let mask = kept.get(index).filter(edge);
        let mut to = mask.map_or(at, |kept| if ahead { kept.1 } else { kept.0 });
        let mut width = 0;
        while let (None, Some(ch)) = (mask, next(to).filter(|&ch| in_word(ch))) {
            if width == LONGEST_WORD {
                return (found, true);
            }
            (to, width) = (step(to, ch), width + 1);
        }
        if to == at {
            break;
        }
        let (start, end) = (at.min(to), at.max(to));
        let kind = mask.and_then(|_| mask_kind(&joined[start..end]));
        found.push(Item {
            start,
            end,
            mask: mask.is_some(),
            kind,
        });
        at = next(to)
            .filter(|ch| JOINTS.contains(ch))
            .map_or(to, |ch| step(to, ch));
    }
    (found, false)
}

/// The class of a mask: a token's kind, or the class whose marker it is.
fn mask_kind(mask: &str) -> Option<EntityKind> {
    let body = mask.strip_prefix(PLACEHOLDER_OPEN);
    EntityKind::ALL.into_iter().find(|&kind| match body {
        Some(body) => body
            .strip_prefix(kind.as_str())
            .is_some_and(|rest| rest.starts_with('_')),
        None => removal_text(kind) == Some(mask),
    })
}

/// The bytes of `from..end` outside every `kept` range, as masks of `kind`.
fn clip(
    kept: &[Kept],
    (mut from, end): (usize, usize),
    kind: Option<EntityKind>,
    masks: &mut Vec<Mask>,
) {
    let first = kept.partition_point(|kept| kept.1 <= from);
    let inside = kept[first..].iter().take_while(|kept| kept.0 < end);
    for (start, stop) in inside.map(|kept| (kept.0, kept.1)).chain([(end, end)]) {
        if from < start {
            masks.push((from, start, kind));
        }
        from = from.max(stop);
    }
}

/// `joined` with each maximal union of `masks` replaced once by the marker of
/// its highest-priority kind; `None` if a range is off a character boundary.
fn write_markers(joined: &str, mut masks: Vec<Mask>) -> Option<String> {
    let rank = |kind: Option<EntityKind>| kind.map_or(u8::MAX, EntityKind::mask_priority);
    masks.sort_unstable_by_key(|&(start, end, kind)| (start, end, rank(kind)));
    let (mut out, mut cursor) = (String::with_capacity(joined.len()), 0);
    let mut masks = masks.into_iter().peekable();
    while let Some((start, mut end, mut kind)) = masks.next() {
        while let Some((_, more, other)) = masks.next_if(|next| next.0 <= end) {
            end = end.max(more);
            kind = if rank(other) < rank(kind) {
                other
            } else {
                kind
            };
        }
        out.push_str(joined.get(cursor..start)?);
        joined.get(start..end)?;
        out.push_str(kind.and_then(removal_text).unwrap_or(VALUE_REMOVED));
        cursor = end;
    }
    out.push_str(&joined[cursor..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::join;

    /// A secret past the read cap withholds the join in any view, whichever
    /// part holds it: here a seam shows one (`My password is ` then the long
    /// value) beside a part that holds a token and a very long word, or beside
    /// a part that holds such a secret on its own (no gate issues that part,
    /// but the join does not lean on it).
    #[test]
    fn a_secret_past_the_read_cap_in_any_view_withholds_the_join() {
        let long = format!("A1{}", "Fake".repeat(275));
        let token = format!("My password: ⟦SECRET_793001BCB097⟧ then {long}");
        for first in [token, format!("My password is {long}")] {
            let parts = [first, "My password is ".to_string(), long.clone()];
            assert_eq!(join(&parts), None, "{}", &parts[0][..20]);
        }
    }
}
