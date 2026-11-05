//! The seams of a join: a value that shows only where two parts meet.
//!
//! Each part of [`SafeText::join`] passed a gate on its own, so a value cut
//! between two parts was never read whole: half an IBAN in each, a label in
//! one and its secret in the next, a URL or a health term cut in two. The join
//! reads the joined text again with the Standard recognisers, names off: the
//! detector of every private gate.
//!
//! It reads the whole text, not a window around each seam. No window bound
//! holds for every recogniser: a table's header line names the column of
//! every row below it, and a quoted record runs on to the line that closes it,
//! however far.
//!
//! What it reads:
//! * three views of the text: as joined, with each blank run that touches a
//!   seam and holds at most one line end as one space, and with that run
//!   deleted. A value cut by a space or a line break between two parts then
//!   reads whole, and a paragraph break stays one. Where the text with a blank
//!   there reads a value across the run, the blank is that value's own, and
//!   the reading without it is dropped;
//! * each token and marker the kernel wrote (the part's [`Origin`]) reads the
//!   way the gate's residue scan reads a token: a stand-in, then a line end.
//!   The last one of a part whose input ended a sentence ends with a paragraph
//!   break instead, so a secret's clause is not read on into the next part. A
//!   token-shaped string a user typed in an open-mode part is plain text;
//! * a span that one part shows on its own was read there by that part's gate,
//!   and stays as that part issued it. A span of a class open mode leaves in
//!   clear stays too when every part it touches is open;
//! * a value a part already masked in part: see `cut_values`.
//!
//! What it writes: every other span is replaced with a fixed marker, the one
//! open mode writes for its class, or [`VALUE_REMOVED`]. The join holds no
//! session key to tokenise the value and no grant to read the mode, so it
//! treats the value as one that never leaves. No byte of a token, a marker or
//! a literal `⟦⟦` is ever rewritten, so every part's tokens restore as before.

use crate::anonymize::PLACEHOLDER_OPEN;
use crate::recognizer::Recognizer;
use crate::recognizers::secrets::value_too_long;
use crate::recognizers::sensitive_terms::{in_word, term_reach, SensitiveTermsRecognizer};
use crate::span::{EntityKind, Span};

use super::detector::Detector;
use super::prohibited::{export_spans, is_hash_fragment, removal_text};
use super::residue::MASKED_STAND_IN;
use super::tokens::session_token_len;
use super::SafeText;

/// The marker for a value of a class that has no removal marker of its own (an
/// e-mail address, a phone number, a URL).
pub(super) const VALUE_REMOVED: &str = "[value removed]";

/// The text a join issues when its seams cannot be read: nothing of its parts.
pub(super) const WITHHELD: &str = "[auxesis: withheld]";

/// How many items a chain or a row reads on each side of a seam: more than the
/// groups of the longest value (an IBAN of 34 characters, in groups of four)
/// and the words of the longest term. A chain that would go on past them
/// withholds the join.
const REACH: usize = 12;

/// The longest word, run or gap the join reads, in characters: a value that
/// may go on in a longer one withholds the join.
const LONGEST_WORD: usize = 512;

/// The characters a value is grouped with inside a part.
const JOINTS: [char; 6] = [' ', '-', '.', '/', '\'', '\u{a0}'];

/// Where the kernel wrote into a text it issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Origin {
    /// The byte ranges of the tokens and markers the kernel wrote, sorted. A
    /// token-shaped string a user typed in open mode is not one of them.
    masks: Vec<(usize, usize)>,
    /// Whether a private gate issued the text, or a part of it: its `⟦⟦` are
    /// literal openers, and no value in it may be left in clear.
    tokenised: bool,
    /// Whether the input ended a sentence: a mask that ends the text is not
    /// read on into what follows it.
    closed: bool,
}

impl Origin {
    /// The origin of `issued`, which a gate wrote for `raw`: a private gate's
    /// tokens (`tokenised`), read as restore reads them, or an open gate's
    /// markers. A marker a user typed reads as one: it holds no value.
    pub(super) fn issued(issued: &str, raw: &str, tokenised: bool) -> Self {
        let masks = marks(issued, tokenised)
            .into_iter()
            .filter(|mark| mark.2)
            .map(|(start, end, _)| (start, end))
            .collect();
        Self {
            masks,
            tokenised,
            closed: closes(raw),
        }
    }

    /// The origin of a fixed marker the kernel wrote, `len` bytes long.
    pub(super) fn marker(len: usize) -> Self {
        Self {
            masks: vec![(0, len)],
            tokenised: false,
            closed: true,
        }
    }
}

/// The marks of a text a gate issued, with whether each is a mask: a token
/// (`tokenised`, a `⟦` that starts one, so `⟦⟦` is a literal opener, `false`)
/// or a marker.
fn marks(text: &str, tokenised: bool) -> Vec<(usize, usize, bool)> {
    let open = PLACEHOLDER_OPEN.len_utf8();
    let markers = || {
        let removed = EntityKind::ALL.into_iter().filter_map(removal_text);
        removed.chain([VALUE_REMOVED, WITHHELD])
    };
    let (mut marks, mut at) = (Vec::new(), 0);
    let first = if tokenised { PLACEHOLDER_OPEN } else { '[' };
    while let Some(offset) = text[at..].find(first) {
        let from = at + offset;
        let rest = &text[from..];
        let mark = match tokenised {
            false => markers()
                .find(|marker| rest.starts_with(marker))
                .map(|marker| (marker.len(), true)),
            true if rest[open..].starts_with(PLACEHOLDER_OPEN) => Some((2 * open, false)),
            true => session_token_len(rest).map(|len| (len, true)),
        };
        at = from + mark.map_or(first.len_utf8(), |mark| mark.0);
        marks.extend(mark.map(|(len, mask)| (from, from + len, mask)));
    }
    marks
}

/// Whether `raw` ends a sentence: with `.`, `!` or `?` after a word of
/// lower-case letters, or with `。`, `！` or `？`. A value (a password, a code) is
/// rarely a lower-case word, so a stop after one is read as the value's own.
fn closes(raw: &str) -> bool {
    let text = raw.trim_end();
    text.ends_with(['。', '！', '？'])
        || text
            .strip_suffix(['.', '!', '?'])
            .and_then(|body| body.split_whitespace().next_back())
            .is_some_and(|word| word.chars().all(char::is_lowercase))
}

/// A byte range of the joined text the join never rewrites.
#[derive(Clone, Copy)]
struct Kept {
    start: usize,
    end: usize,
    /// A token or a marker, read as a stand-in; else a literal `⟦⟦`.
    mask: bool,
    /// The last mask of a part whose input ended a sentence, with only blanks
    /// after it in that part.
    closes: bool,
}

/// A byte range the join masks, with the class whose marker it takes (`None`:
/// [`VALUE_REMOVED`]).
type Mask = (usize, usize, Option<EntityKind>);

/// `parts` joined, with every value only a seam shows replaced by its marker,
/// and the origin of the joined text; `None` when it cannot be read, so
/// nothing of it may leave.
pub(super) fn join(parts: &[SafeText], detector: &dyn Detector) -> Option<(String, Origin)> {
    let joined: String = parts.iter().map(SafeText::as_str).collect();
    let (mut bounds, mut origins, mut at) = (Vec::new(), Vec::new(), 0);
    for part in parts.iter().filter(|part| !part.text.is_empty()) {
        bounds.push((at, at + part.text.len()));
        origins.push(&part.origin);
        at += part.text.len();
    }
    let kept: Vec<Kept> = bounds
        .iter()
        .zip(&origins)
        .flat_map(|(&(start, end), origin)| kept_ranges(&joined[start..end], origin, start))
        .collect();
    let view = stand_in_view(&joined, &kept);
    // A secret past the read cap, in any part or across a seam: refused, like
    // the gate refuses one, never masked in part. One part is checked too.
    if value_too_long(&view) {
        return None;
    }
    let origin = |masks| Origin {
        masks,
        tokenised: origins.iter().any(|origin| origin.tokenised),
        closed: origins.last().is_some_and(|origin| origin.closed),
    };
    if bounds.len() < 2 {
        let masks = kept.iter().filter(|kept| kept.mask);
        return Some((
            joined,
            origin(masks.map(|kept| (kept.start, kept.end)).collect()),
        ));
    }
    let read = |text: &str| -> Option<Vec<Span>> {
        let found = detector.detect(text).ok()?;
        Some(found.into_iter().chain(export_spans(text)).collect())
    };
    let runs = seam_runs(&joined, &bounds);
    // A view whose every run is already written as `with` is the joined text.
    let rewrites = |with: &str| runs.iter().any(|&(start, end)| &joined[start..end] != with);
    // Whether a view with a blank in each run reads a value across it.
    let mut read_across = vec![false; runs.len()];
    let mut spans = Vec::new();
    for with in [None, Some(" "), Some("")] {
        let (text, moved) = match with {
            None => (view.clone(), Vec::new()),
            Some(with) if rewrites(with) => rewrite(&view, &runs, with),
            Some(_) => continue,
        };
        if with.is_some() && value_too_long(&text) {
            return None;
        }
        let width = with.map_or(0, str::len);
        for span in read(&text)? {
            let start = back(&moved, width, span.start, false);
            let end = back(&moved, width, span.end, true);
            let first = runs.partition_point(|run| run.0 <= start);
            let across =
                &mut read_across[first..runs.partition_point(|run| run.1 < end).max(first)];
            // A blank the text reads a value across is that value's own: the
            // reading without it is not the text's.
            if with == Some("") && !across.is_empty() && across.iter().all(|&read| read) {
                continue;
            }
            across.iter_mut().for_each(|read| *read |= with != Some(""));
            spans.push(Span { start, end, ..span });
        }
    }
    let mut alone: Vec<Option<Vec<Span>>> = vec![None; bounds.len()];
    let mut masks = Vec::new();
    for span in spans {
        if span.start >= span.end || is_hash_fragment(&joined, &span) {
            continue;
        }
        let index = bounds.partition_point(|&(_, end)| end <= span.start);
        // Open mode leaves a value of an ordinary class in clear: so does a
        // join of open parts.
        let touched = bounds[index..].iter().zip(&origins[index..]);
        let mut touched = touched.take_while(|((start, _), _)| *start < span.end);
        if !span.is_prohibited() && !touched.any(|(_, origin)| origin.tokenised) {
            continue;
        }
        // A span its part shows on its own stays as that part issued it.
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
    let (text, written) = write_markers(&joined, masks, &kept)?;
    Some((text, origin(written)))
}

/// The kept ranges of a part at `offset` of the joined text: the masks of its
/// origin, and in a tokenised part each literal `⟦⟦` outside them.
fn kept_ranges(text: &str, origin: &Origin, offset: usize) -> Vec<Kept> {
    let range = |(start, end): (usize, usize), mask| Kept {
        start: offset + start,
        end: offset + end,
        mask,
        closes: false,
    };
    let mut kept: Vec<Kept> = origin.masks.iter().map(|&mask| range(mask, true)).collect();
    if origin.tokenised {
        let free = |&&(start, end, _): &&(usize, usize, bool)| {
            let at = origin.masks.partition_point(|mask| mask.1 <= start);
            origin.masks.get(at).is_none_or(|mask| end <= mask.0)
        };
        let literals = marks(text, true);
        let literals = literals.iter().filter(|mark| !mark.2).filter(free);
        kept.extend(literals.map(|&(start, end, _)| range((start, end), false)));
        kept.sort_unstable_by_key(|kept| kept.start);
    }
    if let Some(last) = kept.iter_mut().rev().find(|kept| kept.mask) {
        last.closes = origin.closed && text[last.end - offset..].trim().is_empty();
    }
    kept
}

/// `joined` with each mask of `kept` written as the gate's residue scan reads a
/// token: the stand-in, blanks, then a line end, or a paragraph break for a
/// mask that closes its part. The byte length is unchanged, so an offset in
/// the view is the same offset in `joined`.
fn stand_in_view(joined: &str, kept: &[Kept]) -> String {
    let (mut view, mut from) = (String::with_capacity(joined.len()), 0);
    let stand_in = MASKED_STAND_IN.len_utf8();
    for kept in kept
        .iter()
        .filter(|kept| kept.mask && kept.end - kept.start > stand_in)
    {
        let breaks = if kept.closes && kept.end - kept.start > stand_in + 1 {
            2
        } else {
            1
        };
        view.push_str(&joined[from..kept.start]);
        view.push(MASKED_STAND_IN);
        let blanks = kept.end - kept.start - stand_in - breaks;
        view.extend(std::iter::repeat_n(' ', blanks));
        view.extend(std::iter::repeat_n('\n', breaks));
        from = kept.end;
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

/// Mask what a seam cut off a value a part already masked in part.
///
/// A part may have masked a piece of a value the seam cut: its own gate read
/// that piece, not the value. The rest is then in clear beside the mask, and
/// the recognisers cannot read the whole, because the join holds no key to
/// read what the mask hides. At each seam, with its blank run when that holds
/// at most one line end, and never past a mask that closes its part:
/// * a URL, an e-mail address, a secret, or a value of unknown class next to
///   the gap, with only the tail a part left of it between them, takes that
///   tail and the run of non-blank text on the other side; across a blank, only
///   a run with a digit or a symbol: such a value may go on in any character
///   ([`run`]);
/// * a term of the lexicon a row of words away takes the words of that row
///   the lexicon reads as the rest of it, when they reach across the seam: the
///   rest of the phrase the term starts or ends, then a classifier group; a
///   word glued to the term at the seam is the rest of a word the seam cut
///   ([`term_rows`]);
/// * a value written in groups (a card, an IBAN, an ID, a phone number) takes
///   the groups in a row beside it, one joint apart, when they cross the seam
///   ([`chain`]).
///
/// `None` when such a value may go on past what the join reads: nothing of
/// the join may leave.
fn cut_values(
    joined: &str,
    bounds: &[(usize, usize)],
    kept: &[Kept],
    runs: &[(usize, usize)],
    masks: &mut Vec<Mask>,
) -> Option<()> {
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
        // The masks nearest the gap on each side.
        let before = kept[..kept.partition_point(|kept| kept.end <= gap.0)]
            .last()
            .filter(|kept| kept.mask && !kept.closes);
        let after = kept
            .get(kept.partition_point(|kept| kept.start < gap.1))
            .filter(|kept| kept.mask);
        run(joined, kept, gap, before, after, masks)?;
        term_rows(joined, kept, gap, before, after, masks)?;
        chain(joined, kept, gap, masks)?;
    }
    Some(())
}

/// Whether a value of `kind` may go on in any character, so its end cannot be
/// read from the text after it: a URL, an e-mail address, an IP address, a
/// secret, or a marker of unknown class.
fn run_class(kind: Option<EntityKind>) -> bool {
    matches!(
        kind,
        None | Some(EntityKind::Url | EntityKind::Email | EntityKind::IpV4 | EntityKind::Secret)
    )
}

/// Whether a value of `kind` is written in groups of digits or capitals, so
/// the groups beside its mask may be the rest of it: a card, an IBAN, an ID, a
/// phone number, a date; a marker of unknown class may be any value.
fn grouped_class(kind: Option<EntityKind>) -> bool {
    let terms = SensitiveTermsRecognizer::new();
    kind.is_none_or(|kind| {
        !matches!(
            kind,
            EntityKind::Url
                | EntityKind::Email
                | EntityKind::Secret
                | EntityKind::Address
                | EntityKind::Person
                | EntityKind::Organization
        ) && !terms.kinds().contains(&kind)
    })
}

/// Whether `word` can be a group of a value: it has a digit, or it is two or
/// more capitals.
fn shaped(word: &str) -> bool {
    word.chars().any(char::is_numeric)
        || (word.chars().nth(1).is_some() && word.chars().all(char::is_uppercase))
}

/// The run rule at `gap`: a mask of a run class before it, with only non-blank
/// text between them whose letters and digits are ASCII (`.f`), takes that
/// text and the run of non-blank text after the gap; a mask after it, with
/// only punctuation between them (`://`), takes the run before the gap. Across
/// a blank, that run is taken only when it is ASCII with a digit or a symbol:
/// a plain word stays.
fn run(
    joined: &str,
    kept: &[Kept],
    gap: (usize, usize),
    before: Option<&Kept>,
    after: Option<&Kept>,
    masks: &mut Vec<Mask>,
) -> Option<()> {
    let between = |from: usize, to: usize, letters: bool| {
        let fits =
            |ch: char| !ch.is_whitespace() && (!ch.is_alphanumeric() || (letters && ch.is_ascii()));
        let mut chars = joined[from..to].chars();
        chars.by_ref().take(LONGEST_WORD).all(fits) && chars.next().is_none()
    };
    let rest = |from: usize, to: usize| {
        let text = &joined[from..to];
        let plain = |ch: char| ch.is_ascii_alphabetic() || matches!(ch, '\'' | '-');
        from < to && (gap.0 == gap.1 || (text.is_ascii() && !text.chars().all(plain)))
    };
    let class = |mask: &&Kept| mask_kind(&joined[mask.start..mask.end]);
    let runs = |mask: &&Kept| run_class(class(mask));
    if let Some(mask) = before
        .filter(runs)
        .filter(|mask| between(mask.end, gap.0, true))
    {
        let end = run_end(joined, kept, gap.1, true)?;
        if rest(gap.1, end) {
            clip(kept, (mask.end, end), class(&mask), masks);
        }
    }
    if let Some(mask) = after
        .filter(runs)
        .filter(|mask| between(gap.1, mask.start, false))
    {
        let start = run_end(joined, kept, gap.0, false)?;
        if rest(start, gap.0) {
            clip(kept, (start, mask.start), class(&mask), masks);
        }
    }
    Some(())
}

/// The far end of the run of non-blank text from `at`, up to a kept range:
/// going `ahead`, without the punctuation that ends it; going back, whole.
/// `None` past [`LONGEST_WORD`] characters: the value may go on there.
fn run_end(joined: &str, kept: &[Kept], at: usize, ahead: bool) -> Option<usize> {
    let (mut len, mut word) = (0, 0);
    let mut count = |ch: char| {
        len += ch.len_utf8();
        if ch.is_alphanumeric() {
            word = len;
        }
    };
    let blank = |ch: &char| !ch.is_whitespace();
    let taken = if ahead {
        let stop = kept.get(kept.partition_point(|kept| kept.start < at));
        let text = &joined[at..stop.map_or(joined.len(), |kept| kept.start)];
        text.chars()
            .take_while(blank)
            .take(LONGEST_WORD + 1)
            .map(&mut count)
            .count()
    } else {
        let stop = kept[..kept.partition_point(|kept| kept.end <= at)].last();
        let text = &joined[stop.map_or(0, |kept| kept.end)..at];
        text.chars()
            .rev()
            .take_while(blank)
            .take(LONGEST_WORD + 1)
            .map(&mut count)
            .count()
    };
    if taken > LONGEST_WORD {
        return None;
    }
    Some(if ahead { at + word } else { at - len })
}

/// The term rule at `gap`: a mask of a lexicon class before the gap or after
/// it takes the words of the row from it that the lexicon reads as the rest of
/// its term, when they reach across the gap. A seam may cut a word and put its
/// blank in it, so the row is read as it is, and with the gap deleted when a
/// word (or the mask) ends at it and the next word starts after it.
fn term_rows(
    joined: &str,
    kept: &[Kept],
    gap: (usize, usize),
    before: Option<&Kept>,
    after: Option<&Kept>,
    masks: &mut Vec<Mask>,
) -> Option<()> {
    let terms = SensitiveTermsRecognizer::new();
    for (mask, ahead) in [(before, true), (after, false)] {
        let Some(mask) = mask else { continue };
        let kind = mask_kind(&joined[mask.start..mask.end]);
        if !kind.is_some_and(|kind| terms.kinds().contains(&kind)) {
            continue;
        }
        let edge = if ahead { mask.end } else { mask.start };
        let row = term_row(joined, kept, edge, ahead)?;
        // The edges of the gap and of a word, the one nearest the mask first.
        let (near, far) = if ahead { gap } else { (gap.1, gap.0) };
        let edges =
            |&(start, end): &(usize, usize)| if ahead { (start, end) } else { (end, start) };
        // The words on the mask's side of the gap; a word the gap cuts is past it.
        let side = row
            .iter()
            .take_while(|word| {
                if ahead {
                    word.1 <= gap.0
                } else {
                    gap.1 <= word.0
                }
            })
            .count();
        let meets = near != far
            && row.get(side).is_some_and(|word| edges(word).0 == far)
            && side.checked_sub(1).map_or(edge, |at| edges(&row[at]).1) == near;
        for glued in [false, true] {
            if glued && !meets {
                continue;
            }
            let mut words: Vec<((usize, usize), String)> = row
                .iter()
                .map(|&word| (word, joined[word.0..word.1].to_string()))
                .collect();
            let mut on_side = side;
            if glued && side > 0 {
                let ((first, near_text), (second, far_text)) =
                    (words[side - 1].clone(), words[side].clone());
                let text = if ahead {
                    near_text + &far_text
                } else {
                    far_text + &near_text
                };
                let range = (first.0.min(second.0), first.1.max(second.1));
                words.splice(side - 1..=side, [(range, text)]);
                on_side = side - 1;
            }
            // A word glued to the mask at the seam is the rest of a word it cut.
            let cut = match glued {
                true => side == 0,
                false => {
                    near == far
                        && edge == near
                        && words.first().is_some_and(|(word, _)| edges(word).0 == edge)
                }
            };
            let cut = usize::from(cut);
            let texts: Vec<&str> = words[cut..].iter().map(|(_, text)| text.as_str()).collect();
            let reach = cut + term_reach(&texts, ahead);
            // A blank put in a word right after the term: its rest is the
            // term's only when more of the term follows it.
            if glued && side == 0 && reach == cut {
                continue;
            }
            if reach > on_side {
                let (first, last) = (words[0].0, words[reach - 1].0);
                clip(
                    kept,
                    (first.0.min(last.0), first.1.max(last.1)),
                    kind,
                    masks,
                );
            }
        }
    }
    Some(())
}

/// The words in a row from `at` going `ahead` or back, nearest first: each gap
/// one a term crosses (blanks with at most one line end, a hyphen, an
/// apostrophe), up to a kept range, at most [`REACH`] words. `None` at a word
/// longer than [`LONGEST_WORD`]: the term may go on in it.
fn term_row(joined: &str, kept: &[Kept], at: usize, ahead: bool) -> Option<Vec<(usize, usize)>> {
    let crosses =
        |ch: char| ch.is_whitespace() || matches!(ch, '-' | '\'' | '\u{2019}' | '\u{02BC}');
    let chars: Vec<(usize, char)> = if ahead {
        let stop = kept.get(kept.partition_point(|kept| kept.start < at));
        let text = &joined[at..stop.map_or(joined.len(), |kept| kept.start)];
        let chars = text.char_indices().map(|(offset, ch)| (at + offset, ch));
        chars.take(REACH * 2 * (LONGEST_WORD + 1)).collect()
    } else {
        let stop = kept[..kept.partition_point(|kept| kept.end <= at)].last();
        let from = stop.map_or(0, |kept| kept.end);
        let chars = joined[from..at].char_indices().rev();
        chars
            .map(|(offset, ch)| (from + offset, ch))
            .take(REACH * 2 * (LONGEST_WORD + 1))
            .collect()
    };
    let (mut row, mut word, mut width, mut gap, mut breaks) = (Vec::new(), None, 0, 0, 0);
    for (offset, ch) in chars {
        let range = (offset, offset + ch.len_utf8());
        if in_word(ch) {
            if width == LONGEST_WORD {
                return None;
            }
            word = Some(word.map_or(range, |(start, end): (usize, usize)| {
                (start.min(range.0), end.max(range.1))
            }));
            width += 1;
            continue;
        }
        if let Some(found) = word.take() {
            row.push(found);
            (width, gap, breaks) = (0, 0, 0);
            if row.len() == REACH {
                return Some(row);
            }
        }
        gap += 1;
        breaks += usize::from(ch == '\n');
        if !crosses(ch) || breaks > 1 || gap > LONGEST_WORD {
            return Some(row);
        }
    }
    row.extend(word);
    Some(row)
}

/// A word, or a mask a part carries, in the chain around a seam.
#[derive(Clone, Copy)]
struct Item {
    start: usize,
    end: usize,
    mask: bool,
    /// A mask that closes its part.
    closes: bool,
    /// The class of a mask; `None` for a word, or a marker of no class.
    kind: Option<EntityKind>,
}

/// Why a row of items stopped.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// No item follows.
    End,
    /// [`REACH`] items were read and one more follows.
    Cap,
    /// The next word is longer than [`LONGEST_WORD`].
    Long,
}

/// The chain rule at `gap`: the masks and groups in a row on each side of it,
/// when the two nearest it go on with one value and the chain holds a mask of
/// a grouped class, are masked from the first to the last, all but their
/// masks. `None` when the chain runs on past what the join reads: the value
/// may go on there.
fn chain(joined: &str, kept: &[Kept], gap: (usize, usize), masks: &mut Vec<Mask>) -> Option<()> {
    let (mut from, mut to) = gap;
    // One joint on either side may be the value's own: `3456` then `-7899`.
    // Across a blank, a stop or a quote ends a sentence, not a group.
    let joints: &[char] = if from == to { &JOINTS } else { &['-', '/'] };
    let joint = |ch: Option<char>| {
        ch.filter(|ch| joints.contains(ch))
            .map_or(0, char::len_utf8)
    };
    let skipped = joint(joined[..from].chars().next_back());
    from -= skipped;
    if skipped == 0 {
        to += joint(joined[to..].chars().next());
    }
    let sides = [
        items(joined, kept, from, false),
        items(joined, kept, to, true),
    ];
    let shaped = |item: &Item| !item.mask && shaped(&joined[item.start..item.end]);
    let grouped = |item: &Item| item.mask && grouped_class(item.kind);
    let (Some(&left), Some(&right)) = (sides[0].0.first(), sides[1].0.first()) else {
        // A grouped mask beside a word too long to read: the value may go on in it.
        let beside = sides
            .iter()
            .any(|(side, _)| side.first().is_some_and(grouped));
        let long = sides
            .iter()
            .any(|(side, stop)| side.is_empty() && *stop == Stop::Long);
        return (!(beside && long)).then_some(());
    };
    let crosses = match (left.mask, right.mask) {
        (true, true) => false,
        // The two words at the seam read as one, since the seam may cut one.
        (false, false) => {
            let text = |item: &Item| &joined[item.start..item.end];
            let caps = |item: &Item| {
                text(item)
                    .chars()
                    .all(|ch| ch.is_uppercase() || ch.is_numeric())
            };
            caps(&left) && caps(&right) && self::shaped(&format!("{}{}", text(&left), text(&right)))
        }
        (true, false) => grouped(&left) && !left.closes && shaped(&right),
        (false, true) => grouped(&right) && shaped(&left),
    };
    if !crosses {
        return Some(());
    }
    let (mut chain, mut runs_on) = (vec![left, right], false);
    for (side, stop) in &sides {
        let taken = side[1..]
            .iter()
            .take_while(|item| item.mask || shaped(item))
            .count();
        chain.extend(&side[1..=taken]);
        runs_on |= taken + 1 == side.len() && *stop != Stop::End;
    }
    if !chain.iter().any(grouped) {
        return Some(());
    }
    if runs_on {
        return None;
    }
    let kinds = chain
        .iter()
        .filter(|item| item.mask)
        .filter_map(|item| item.kind);
    let kind = kinds.min_by_key(|kind| kind.mask_priority());
    let start = chain.iter().map(|item| item.start).min()?;
    let end = chain.iter().map(|item| item.end).max()?;
    clip(kept, (start, end), kind, masks);
    Some(())
}

/// The items in a row from `at`, going `ahead` or back: masks and words, each
/// one joint character from the next, or glued to a mask; at most [`REACH`],
/// and why the row stopped.
fn items(joined: &str, kept: &[Kept], mut at: usize, ahead: bool) -> (Vec<Item>, Stop) {
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
    loop {
        let index = kept.partition_point(|kept| {
            if ahead {
                kept.start < at
            } else {
                kept.end < at
            }
        });
        let edge = |kept: &&Kept| kept.mask && at == if ahead { kept.start } else { kept.end };
        let mask = kept.get(index).filter(edge);
        if mask.is_none() && !next(at).is_some_and(in_word) {
            return (found, Stop::End);
        }
        if found.len() == REACH {
            return (found, Stop::Cap);
        }
        let mut to = mask.map_or(at, |kept| if ahead { kept.end } else { kept.start });
        let mut width = 0;
        while let (None, Some(ch)) = (mask, next(to).filter(|&ch| in_word(ch))) {
            if width == LONGEST_WORD {
                return (found, Stop::Long);
            }
            (to, width) = (step(to, ch), width + 1);
        }
        let (start, end) = (at.min(to), at.max(to));
        found.push(Item {
            start,
            end,
            mask: mask.is_some(),
            closes: mask.is_some_and(|kept| kept.closes),
            kind: mask.and_then(|_| mask_kind(&joined[start..end])),
        });
        at = next(to)
            .filter(|ch| JOINTS.contains(ch))
            .map_or(to, |ch| step(to, ch));
    }
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
    let first = kept.partition_point(|kept| kept.end <= from);
    let inside = kept[first..].iter().take_while(|kept| kept.start < end);
    for (start, stop) in inside
        .map(|kept| (kept.start, kept.end))
        .chain([(end, end)])
    {
        if from < start {
            masks.push((from, start, kind));
        }
        from = from.max(stop);
    }
}

/// `joined` with each maximal union of `masks` replaced once by the marker of
/// its highest-priority kind, and the masks of the result: each mask of `kept`,
/// moved, and each marker written. `None` if a range is off a character
/// boundary.
fn write_markers(
    joined: &str,
    mut masks: Vec<Mask>,
    kept: &[Kept],
) -> Option<(String, Vec<(usize, usize)>)> {
    let rank = |kind: Option<EntityKind>| kind.map_or(u8::MAX, EntityKind::mask_priority);
    masks.sort_unstable_by_key(|&(start, end, kind)| (start, end, rank(kind)));
    let (mut out, mut written, mut cursor) = (String::with_capacity(joined.len()), Vec::new(), 0);
    let mut masks = masks.into_iter().peekable();
    let mut moved = kept.iter().filter(|kept| kept.mask).peekable();
    loop {
        let next = masks.next();
        let to = next.map_or(joined.len(), |mask| mask.0);
        // A kept range is never inside a mask, so each one before `to` is copied.
        while let Some(kept) = moved.next_if(|kept| kept.end <= to) {
            let at = out.len() + kept.start - cursor;
            written.push((at, at + kept.end - kept.start));
        }
        out.push_str(joined.get(cursor..to)?);
        let Some((start, mut end, mut kind)) = next else {
            break;
        };
        while let Some((_, more, other)) = masks.next_if(|next| next.0 <= end) {
            end = end.max(more);
            kind = if rank(other) < rank(kind) {
                other
            } else {
                kind
            };
        }
        joined.get(start..end)?;
        let at = out.len();
        out.push_str(kind.and_then(removal_text).unwrap_or(VALUE_REMOVED));
        written.push((at, out.len()));
        cursor = end;
    }
    Some((out, written))
}

#[cfg(test)]
mod tests {
    use super::{join, Origin, WITHHELD};
    use crate::safetext::detector::{without_names, Detector, StandardDetector};
    use crate::safetext::{DetectError, NameCoverage, SafeText};
    use crate::span::Span;

    /// A part as a gate issues `text`: its tokens are the kernel's
    /// (`tokenised`), else its markers.
    fn part(text: &str, tokenised: bool) -> SafeText {
        SafeText {
            text: text.to_string(),
            names: NameCoverage::Checked,
            origin: Origin::issued(text, text, tokenised),
        }
    }

    fn standard() -> std::sync::Arc<dyn Detector> {
        without_names(StandardDetector::new())
    }

    /// A secret past the read cap withholds the join in any view, whichever
    /// part holds it: here a seam shows one (`My password is ` then the long
    /// value) beside a part that holds a token and a very long word, or beside
    /// a part that holds such a secret on its own (no gate issues that part,
    /// but the join does not lean on it). A join of that part alone is read
    /// too.
    #[test]
    fn a_secret_past_the_read_cap_in_any_view_withholds_the_join() {
        let long = format!("A1{}", "Fake".repeat(275));
        let token = format!("My password: ⟦SECRET_793001BCB097⟧ then {long}");
        for first in [token, format!("My password is {long}")] {
            let parts = [first, "My password is ".to_string(), long.clone()];
            let parts = parts.map(|text| part(&text, true));
            assert_eq!(
                join(&parts, standard().as_ref()),
                None,
                "{}",
                &parts[0].text[..20]
            );
        }
        let alone = part(&format!("My password is {long}"), false);
        assert_eq!(join(&[alone, part("", false)], standard().as_ref()), None);
    }

    /// A detector that fails on every text.
    struct Failing;

    impl Detector for Failing {
        fn detect(&self, _: &str) -> Result<Vec<Span>, DetectError> {
            Err(DetectError::Panicked)
        }
    }

    /// A detector error on the joined text withholds the join: nothing is
    /// issued that was not read.
    #[test]
    fn a_detector_error_withholds_the_join() {
        let parts = [part("Call me at ", false), part("+33 6 12 34 56 78", false)];
        assert_eq!(join(&parts, &Failing), None);
        let parts = [part("Hello", true), part(" there.", true)];
        assert_eq!(join(&parts, &Failing), None);
    }

    /// A chain of groups beside a mask that runs on past [`super::REACH`]
    /// items withholds the join: its tail would be left in clear.
    #[test]
    fn a_chain_past_the_read_reach_withholds_the_join() {
        let groups: Vec<String> = (0..20).map(|at| format!("A{at:X}{}", at % 10)).collect();
        let parts = [
            part("Ref ⟦PHONE_0123456789AB⟧", true),
            part(&format!("-{} ok.", groups.join(" ")), true),
        ];
        assert_eq!(join(&parts, standard().as_ref()), None);
        let short = [
            parts[0].clone(),
            part(&format!("-{} ok.", groups[..4].join(" ")), true),
        ];
        let (text, _) = join(&short, standard().as_ref()).expect("read");
        assert_eq!(text, "Ref ⟦PHONE_0123456789AB⟧[value removed] ok.");
        let open = [part("Ma carte [card removed]", false), parts[1].clone()];
        assert_eq!(join(&open, standard().as_ref()), None);
    }

    /// A token-shaped string a user typed in an open-mode part is read as text,
    /// never kept as a stand-in: the kernel minted no token there.
    #[test]
    fn a_typed_token_in_an_open_part_is_read_as_text() {
        let typed = part("⟦CREDIT_CARD_345678991234⟧ ok.", false);
        assert!(typed.origin.masks.is_empty());
        let minted = part("⟦CREDIT_CARD_345678991234⟧ ok.", true);
        assert_eq!(minted.origin.masks, [(0, 30)]);
        let parts = [part("Ref 4000 0012 ", false), typed];
        let (text, origin) = join(&parts, standard().as_ref()).expect("read");
        assert_eq!(text, "Ref 4000 0012 ⟦CREDIT_CARD_345678991234⟧ ok.");
        assert!(origin.masks.is_empty());
    }

    /// The joined text's origin holds every mask of its parts, moved, and
    /// each marker the join wrote; a withheld join is one marker.
    #[test]
    fn the_origin_of_a_join_holds_its_parts_masks_and_its_markers() {
        let parts = [
            part("Ref ⟦PHONE_0123456789AB⟧", true),
            part("-99 then ⟦EMAIL_0123456789AB⟧.", true),
        ];
        let (text, origin) = join(&parts, standard().as_ref()).expect("read");
        assert_eq!(
            text,
            "Ref ⟦PHONE_0123456789AB⟧[value removed] then ⟦EMAIL_0123456789AB⟧."
        );
        let shown: Vec<&str> = origin
            .masks
            .iter()
            .map(|&(start, end)| &text[start..end])
            .collect();
        assert_eq!(
            shown,
            [
                "⟦PHONE_0123456789AB⟧",
                "[value removed]",
                "⟦EMAIL_0123456789AB⟧"
            ]
        );
        assert_eq!(Origin::marker(WITHHELD.len()).masks, [(0, WITHHELD.len())]);
    }
}
