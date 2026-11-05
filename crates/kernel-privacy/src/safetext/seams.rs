//! The seams of [`SafeText::join`](super::SafeText::join): where two issued
//! parts meet with no blank between them, a value cut in two could show again.
//! The run across the seam is read again, with [`WINDOW_CHARS`] characters on
//! each side, as the gate's residue scan reads issued text. Only a run may
//! change, and never the tokens and markers the kernel wrote in it (its marks).

use std::iter::once;

use kernel_core::privacy::GrantPolicy;

use super::detector::Detector;
use super::prohibited::removal_text;
use super::residue::MASKED_STAND_IN;
use super::tokens::session_token_len;
use crate::anonymize::PLACEHOLDER_OPEN;
use crate::recognizers::secrets::value_too_long;
use crate::span::{EntityKind, Span};

/// A byte range of a text.
pub(super) type Mark = (usize, usize);
/// Byte ranges, sorted and disjoint, of the tokens and markers the kernel wrote.
pub(super) type Marks = Vec<Mark>;

/// What a join writes in place of the clear text of a seam run it hides.
pub(super) const VALUE_REMOVED: &str = "[value removed]";
/// What a join issues when it cannot hide what crosses a seam.
pub(super) const WITHHELD: &str = "[auxesis: withheld]";
/// The longest seam run a join reads; a longer one withholds the join.
pub(super) const MAX_RUN_BYTES: usize = 512;
/// How many characters a join reads on each side of a seam run.
const WINDOW_CHARS: usize = 40;

/// The marks of a text a gate under `policy` issued. A tokenising gate doubles
/// a typed `⟦`, so read left to right, any other `⟦` opens one of its tokens.
/// A passthrough gate mints none: its marks are its removal markers.
pub(super) fn marks(policy: GrantPolicy, text: &str) -> Marks {
    let (mut marks, mut at) = (Vec::new(), 0);
    let tokens = policy == GrantPolicy::Tokenised;
    let open = if tokens { PLACEHOLDER_OPEN } else { '[' };
    while let Some(offset) = text[at..].find(open) {
        let start = at + offset;
        let rest = &text[start..];
        if tokens && rest[open.len_utf8()..].starts_with(open) {
            at = start + 2 * open.len_utf8();
            continue;
        }
        let len = match tokens {
            true => session_token_len(rest),
            false => EntityKind::ALL
                .into_iter()
                .filter_map(removal_text)
                .find(|marker| rest.starts_with(marker))
                .map(str::len),
        };
        if let Some(len) = len {
            marks.push((start, start + len));
        }
        at = start + len.unwrap_or(open.len_utf8());
    }
    marks
}

/// The joined `text` and its `marks` as the join issues them: the clear pieces
/// of each run across one of the `seams` that holds a mark or a value become
/// [`VALUE_REMOVED`]. [`WITHHELD`] when a run is longer than [`MAX_RUN_BYTES`],
/// when a prohibited value in a run goes on past it (rewriting the run would
/// leave the rest readable), when the recognisers fail, or when the text holds
/// a secret longer than the gate reads.
pub(super) fn mend(
    text: &str,
    marks: &[Mark],
    seams: &[usize],
    detector: &dyn Detector,
) -> (String, Marks) {
    let withheld = || (WITHHELD.to_string(), vec![(0, WITHHELD.len())]);
    let Some(pieces) = hidden(text, marks, seams, detector) else {
        return withheld();
    };
    let (text, marks) = rewrite(text, marks, &pieces);
    // The gate's long-secret check, each mark read as an opaque word of its
    // length: ASCII text keeps the check's fast path.
    let mut view = text.clone().into_bytes();
    marks
        .iter()
        .for_each(|&(start, end)| view[start..end].fill(b'x'));
    match String::from_utf8(view).map(|view| value_too_long(&view)) {
        Ok(false) => (text, marks),
        _ => withheld(),
    }
}

/// The clear pieces of every seam run the join hides, in order; `None` withholds.
fn hidden(text: &str, marks: &[Mark], seams: &[usize], scan: &dyn Detector) -> Option<Vec<Mark>> {
    let (mut pieces, mut read_to) = (Vec::new(), 0);
    for &seam in seams {
        // A seam on a blank changes nothing, and one in a run already read
        // belongs to it. A mark never starts or ends with a blank.
        if seam < read_to
            || text[..seam].ends_with(char::is_whitespace)
            || text[seam..].starts_with(char::is_whitespace)
        {
            continue;
        }
        let (start, end) = run(text, marks, seam)?;
        read_to = end;
        let (spans, (run_start, run_end)) = read(text, marks, (start, end), scan)?;
        let meets = |span: &Span| span.start < run_end && run_start < span.end;
        let past = |span: &Span| span.start < run_start || run_end < span.end;
        if spans
            .iter()
            .any(|span| meets(span) && span.is_prohibited() && past(span))
        {
            return None;
        }
        let inner = &marks[marks.partition_point(|m| m.1 <= start)..];
        let inner = &inner[..inner.partition_point(|m| m.0 < end)];
        if !inner.is_empty() || spans.iter().any(meets) {
            let starts = once(start).chain(inner.iter().map(|m| m.1));
            let ends = inner.iter().map(|m| m.0).chain(once(end));
            pieces.extend(starts.zip(ends).filter(|(from, to)| from < to));
        }
    }
    Some(pieces)
}

/// The run around `seam`: the stretch with no blank outside a mark. `None` when
/// it is longer than [`MAX_RUN_BYTES`].
fn run(text: &str, marks: &[Mark], seam: usize) -> Option<Mark> {
    let inside = |at: usize| {
        let next = marks.partition_point(|m| m.1 <= at);
        marks.get(next).is_some_and(|m| m.0 <= at)
    };
    let blank = |&(at, ch): &(usize, char)| ch.is_whitespace() && !inside(at);
    let mut before = text[..seam].char_indices().rev();
    let mut after = text[seam..].char_indices().map(|(at, ch)| (seam + at, ch));
    let start = before.find(blank).map_or(0, |(at, ch)| at + ch.len_utf8());
    let end = after.find(blank).map_or(text.len(), |(at, _)| at);
    (end - start <= MAX_RUN_BYTES).then_some((start, end))
}

/// The values the private recognisers read in the run `start..end`, with up to
/// [`WINDOW_CHARS`] characters on each side (every mark whole), and the run's
/// place in what they read. `None` when they fail.
fn read(
    text: &str,
    marks: &[Mark],
    (start, end): Mark,
    scan: &dyn Detector,
) -> Option<(Vec<Span>, Mark)> {
    let before = text[..start].char_indices().rev().nth(WINDOW_CHARS - 1);
    let after = text[end..].char_indices().nth(WINDOW_CHARS);
    // A window edge inside a mark moves out to the edge of that mark.
    let around = |at: usize| {
        let next = marks.partition_point(|m| m.1 <= at);
        marks.get(next).filter(|m| m.0 < at)
    };
    let from = before.map_or(0, |(at, _)| at);
    let from = around(from).map_or(from, |m| m.0);
    let to = after.map_or(text.len(), |(at, _)| end + at);
    let to = around(to).map_or(to, |m| m.1);
    let mut view = String::new();
    push_view(&mut view, text, marks, (from, start));
    let run_start = view.len();
    push_view(&mut view, text, marks, (start, end));
    let run = (run_start, view.len());
    push_view(&mut view, text, marks, (end, to));
    Some((scan.residue(&view).ok()?, run))
}

/// Appends `text[from..to]` (whole marks) to `view` as the residue scan reads
/// issued text: each mark is the stand-in and a line end, so a label before it
/// takes the stand-in as its value, never the next word.
fn push_view(view: &mut String, text: &str, marks: &[Mark], (from, to): Mark) {
    let mut at = from;
    let first = marks.partition_point(|m| m.1 <= from);
    for &(start, end) in marks[first..].iter().take_while(|m| m.0 < to) {
        view.push_str(&text[at..start]);
        view.extend([MASKED_STAND_IN, '\n']);
        at = end;
    }
    view.push_str(&text[at..to]);
}

/// `text` with each piece replaced by [`VALUE_REMOVED`], and the marks moved
/// with it, one more for each marker written.
fn rewrite(text: &str, marks: &[Mark], pieces: &[Mark]) -> (String, Marks) {
    let mut out = String::with_capacity(text.len());
    let mut kept = Vec::with_capacity(marks.len() + pieces.len());
    let (mut from, mut next) = (0, 0);
    for &(start, end) in pieces.iter().chain(once(&(text.len(), text.len()))) {
        let base = out.len();
        while next < marks.len() && marks[next].1 <= start {
            kept.push((base + marks[next].0 - from, base + marks[next].1 - from));
            next += 1;
        }
        out.push_str(&text[from..start]);
        if start < end {
            kept.push((out.len(), out.len() + VALUE_REMOVED.len()));
            out.push_str(VALUE_REMOVED);
        }
        from = end;
    }
    (out, kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safetext::DetectError;

    struct Failing;

    impl Detector for Failing {
        fn detect(&self, _: &str) -> Result<Vec<Span>, DetectError> {
            Err(DetectError::Panicked)
        }
    }

    #[test]
    fn a_glued_seam_and_a_long_secret_fail_closed() {
        let glued = |text: &str| mend(text, &[], &[3], &Failing).0;
        assert_eq!([glued("abcdef"), glued("abc def")], [WITHHELD, "abc def"]);
        // The long-secret check reads the joined text, whatever its seams.
        let long = format!("password: {}", "word ".repeat(250));
        assert_eq!(mend(&long, &[], &[], &Failing).0, WITHHELD);
    }
}
