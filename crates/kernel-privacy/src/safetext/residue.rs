//! The residue scan's view of a masked string: token stand-ins, clear parts, and
//! the mapping from a residue hit back to the original text.

use std::borrow::Cow;

use crate::anonymize::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
use crate::span::{EntityKind, Span};

/// The stand-in for a masked token in the clear text of the residue scan. It is
/// one character that is not a blank, so a value rule reads the token's place as
/// a value's place: the blank it replaces let a rule's separator skip into the
/// next word (`password: ⟦…⟧ tous` read `tous` as a value). A hit that holds the
/// stand-in is the masked token's own value, never residue.
pub(super) const MASKED_STAND_IN: char = '\u{E000}';

/// Rounds that mask a secret residue before the gate refuses the text.
pub(super) const RESIDUE_ROUNDS: usize = 3;

/// The clear bytes of each residue `hits` (offsets in the clear text of `masked`),
/// as spans of `text` of the hit's class, the string `masked` was made from with the
/// per-token `occurrences`. A secret runs on to the end of its line in `text`: the
/// stand-in's line break may have cut it short there. Any other class is the hit's
/// own bytes: its rule read the whole value, and the next round scans again. A clear
/// byte has the same length in both texts (`⟦⟦` reads as `⟦`, a typed stand-in as
/// U+FFFD, a blanked token as blanks).
pub(super) fn residue_in_text(
    text: &str,
    masked: &str,
    occurrences: &[(String, String)],
    hits: &[&Span],
) -> Vec<Span> {
    // Clear stretches: (offset in the clear text, offset in `text`, length).
    let (mut stretches, mut view, mut at) = (Vec::<(usize, usize, usize)>::new(), 0, 0);
    let mut surfaces = occurrences.iter().map(|(_, surface)| surface.len());
    let mut chars = masked.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == PLACEHOLDER_OPEN && chars.peek() != Some(&PLACEHOLDER_OPEN) {
            chars.by_ref().find(|&inner| inner == PLACEHOLDER_CLOSE);
            view += MASKED_STAND_IN.len_utf8() + 1;
            at += surfaces.next().unwrap_or(0);
            continue;
        }
        if ch == PLACEHOLDER_OPEN {
            chars.next();
        }
        match stretches.last_mut() {
            Some(last) if last.0 + last.2 == view && last.1 + last.2 == at => {
                last.2 += ch.len_utf8();
            }
            _ => stretches.push((view, at, ch.len_utf8())),
        }
        (view, at) = (view + ch.len_utf8(), at + ch.len_utf8());
    }
    let mut found = Vec::new();
    for hit in hits {
        // Stretches are sorted: a binary search, then only the ones the hit overlaps.
        let first = stretches.partition_point(|&(from, _, len)| from + len <= hit.start);
        for &(from, to, len) in stretches[first..].iter().take_while(|s| s.0 < hit.end) {
            let (start, end) = (hit.start.max(from), hit.end.min(from + len));
            if start < end && to + len <= text.len() {
                found.push((to + start - from, to + end - from, hit.kind));
            }
        }
    }
    let mut spans: Vec<Span> = found
        .extract_if(.., |(_, _, kind)| *kind != EntityKind::Secret)
        .map(|(start, end, kind)| Span::new(kind, start, end, 1.0, "residue"))
        .collect();
    // Each line end is searched from the furthest point reached, and each line's trimmed
    // end is found once, from its first hit: one pass over `text`. Hits are sorted, so a
    // later hit on the same line starts at or after that first one, and its trimmed end is
    // the larger of its start and the line's.
    found.sort_unstable_by_key(|&(start, end, _)| (start, end));
    let (mut reach, mut trimmed) = (0, (usize::MAX, 0));
    for (start, end, _) in found {
        let from = start.max(reach).min(text.len());
        let line = text[from..].find('\n').map_or(text.len(), |n| from + n);
        if trimmed.0 != line {
            trimmed = (line, start + text[start..line].trim_end().len());
        }
        let end = end.max(start.max(trimmed.1));
        reach = reach.max(line);
        spans.push(Span::new(EntityKind::Secret, start, end, 1.0, "residue"));
    }
    spans
}

/// K-RESIDUE-URL: the rest of each residue URL in `more` that a masked secret
/// cut short. A secret's stand-in ends its line in the residue view, so a URL
/// read there stops at the secret, while the URL rule, reading the text itself,
/// runs on through it (`…?key=<secret>&alt=json`). Past each secret span the URL
/// is the run of URL characters up to a blank, a URL stop or the next masked
/// span; it runs on through every secret span it meets. These tails are only
/// added: no span is removed or narrowed.
pub(super) fn url_tails(text: &str, spans: &[Span], more: &[Span]) -> Vec<Span> {
    let mut tails = Vec::new();
    if !more.iter().any(|span| span.kind == EntityKind::Url) {
        return tails;
    }
    // Secret spans merged into disjoint ranges, and every span's start, sorted.
    let mut secrets: Vec<(usize, usize)> = spans
        .iter()
        .filter(|span| span.kind == EntityKind::Secret)
        .map(|span| (span.start, span.end))
        .collect();
    secrets.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(secrets.len());
    for (start, end) in secrets {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let mut starts: Vec<usize> = spans.iter().map(|span| span.start).collect();
    starts.sort_unstable();
    let stop = |ch: char| ch.is_whitespace() || matches!(ch, '<' | '>' | '"' | '\'' | ')');
    let mut ends: Vec<usize> = more
        .iter()
        .filter(|span| span.kind == EntityKind::Url)
        .map(|span| span.end)
        .collect();
    ends.sort_unstable();
    // A walk covers every URL end it passes: each byte is walked once (linear).
    let mut reach = 0;
    for mut at in ends {
        if at < reach {
            continue;
        }
        // Each step moves past one merged secret range, so this ends.
        while let Some(&(_, end)) = merged
            .get(merged.partition_point(|&(_, end)| end <= at))
            .filter(|&&(start, _)| start <= at)
        {
            at = end.min(text.len());
            let next = starts
                .get(starts.partition_point(|&s| s < at))
                .map_or(text.len(), |&s| s.min(text.len()));
            let run = text.get(at..next).unwrap_or("");
            // The URL rule reads through a Unicode space between two ASCII letters
            // or digits (the folded view drops it), so the tail does too.
            let glued = |i: usize, ch: char| {
                crate::normalize::is_unicode_space(ch)
                    && text[..at + i]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_ascii_alphanumeric())
                    && text[at + i + ch.len_utf8()..]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphanumeric())
            };
            let found = run
                .char_indices()
                .find(|&(i, ch)| stop(ch) && !glued(i, ch));
            let found = found.map(|(i, _)| i);
            let Some(cut) = found.or((next == text.len()).then_some(run.len())) else {
                // The run reaches the next masked span: the URL may go on past it.
                if next > at {
                    tails.push(Span::new(EntityKind::Url, at, next, 1.0, "residue"));
                }
                at = next;
                continue;
            };
            // The URL ends here: the URL rule's trailing punctuation stays out.
            let cut = run[..cut]
                .trim_end_matches(['.', ',', ';', ':', '!', '?'])
                .len();
            if cut > 0 {
                tails.push(Span::new(EntityKind::Url, at, at + cut, 1.0, "residue"));
            }
            break;
        }
        reach = at;
    }
    tails
}

/// Whether a residue hit is only stand-ins: every character is a masked token's
/// stand-in, so the hit is that token's own place. A hit with any other character,
/// even one next to a stand-in, is a value left in clear.
pub(super) fn is_stand_in_only(hit: &str) -> bool {
    !hit.is_empty() && hit.chars().all(|ch| ch == MASKED_STAND_IN)
}

/// The clear text of a masked string, read the way [`Anonymizer::restore`]
/// reads it: a doubled opener is one literal `⟦`, and each placeholder becomes
/// [`MASKED_STAND_IN`], so its hex fingerprint never reads as a value in the
/// residue scan.
///
/// Not a line break: a line break starts a new line for the e-mail layer's line
/// heuristics, which then read the words that follow a token as names
/// (`…⟦TOKEN⟧): Find places matching a name` gave `name` as a person) and refused
/// text the first pass had already masked correctly.
pub(super) fn clear_parts(masked: &str) -> Cow<'_, str> {
    if !masked.contains(MASKED_STAND_IN) && !masked.contains(PLACEHOLDER_OPEN) {
        return Cow::Borrowed(masked);
    }
    let mut clear = String::with_capacity(masked.len());
    let mut chars = masked.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == MASKED_STAND_IN {
            // Typed text, not a token: it keeps a character that is no stand-in.
            clear.push('\u{FFFD}');
        } else if ch != PLACEHOLDER_OPEN {
            clear.push(ch);
        } else if chars.peek() == Some(&PLACEHOLDER_OPEN) {
            chars.next();
            clear.push(PLACEHOLDER_OPEN);
        } else {
            // The stand-in ends its line in the clear text. A masked value ran to
            // the end of its line, and a merged span may have eaten the line break:
            // the residue scan must not read the next line as that value.
            clear.push(MASKED_STAND_IN);
            clear.push('\n');
            for inner in chars.by_ref() {
                if inner == PLACEHOLDER_CLOSE {
                    break;
                }
            }
        }
    }
    Cow::Owned(clear)
}
