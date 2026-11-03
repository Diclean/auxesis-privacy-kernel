//! One decoding pass: entities, escapes and markers folded into a mapped view.

use crate::anonymize::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};

use super::escapes::{common_escape, decode_percent_run, percent_run_end, EscapeParser};
use super::html_entities::decode_entity;

/// What a view does with a token marker.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Markers {
    /// A `⟦…⟧` pair goes with its content, a lone bracket alone.
    Drop,
    /// Only the brackets go.
    Brackets,
    /// Each bracket reads as a space.
    Space,
}

/// One pass: the decoded text, the source range of each of its characters,
/// whether a `⟦…⟧` pair was dropped with its content, and the dropped markers.
pub(super) type Pass = (String, Vec<(usize, usize)>, bool, Vec<(usize, usize)>);

/// One decoding pass over `source`.
///
/// Returns the decoded text and, for every character of it, the byte range in
/// `source` it came from. Named and numeric entities are decoded everywhere;
/// percent escapes only inside a URL token; markers and hidden characters are
/// dropped (see the module docs). A malformed escape stays literal and
/// never blocks the valid escapes around it, and every character a percent run
/// produced carries the run's full source range (conservative bounds).
pub(super) fn decode_once(source: &str, mode: Markers, escape: Option<&EscapeParser<'_>>) -> Pass {
    let urls = url_ranges(source);
    let mut text = String::with_capacity(source.len());
    let mut bounds: Vec<(usize, usize)> = Vec::with_capacity(source.len());
    let mut index = 0usize;
    // `urls` is sorted and disjoint, so a single forward cursor replaces a scan
    // of every range at every escape: the pass stays linear on a text with many
    // escapes and many URLs.
    let mut url_cursor = 0usize;
    // Start of the dropped bytes not yet attributed to a kept character.
    let mut hidden: Option<usize> = None;
    // The nearest `⟧` at or after the cursor, found once per bracket: linear.
    let mut next_close: Option<Option<usize>> = None;
    let mut dropped_body = false;
    let mut markers: Vec<(usize, usize)> = Vec::new();
    while index < source.len() {
        while url_cursor < urls.len() && index >= urls[url_cursor].1 {
            url_cursor += 1;
        }
        let in_url = url_cursor < urls.len() && index >= urls[url_cursor].0;
        let ch = source[index..]
            .chars()
            .next()
            .expect("index is on a char boundary");
        if ch == '\\' || ch == '%' {
            if let Some((decoded, end)) = escape
                .and_then(|parse| {
                    common_escape(source, index)
                        .or_else(|| (ch == '\\').then(|| parse(source, index)).flatten())
                })
                .filter(|(_, end)| *end > index && source.is_char_boundary(*end))
            {
                push_decoded(
                    &mut text,
                    &mut bounds,
                    &mut hidden,
                    decoded.encode_utf8(&mut [0; 4]),
                    (index, end),
                );
                index = end;
                continue;
            }
        }
        // A `⟦…⟧` pair (nearest `⟧`, any content) or a lone bracket is dropped.
        // A bracket an entity produced is kept for the next pass.
        if ch == PLACEHOLDER_OPEN || ch == PLACEHOLDER_CLOSE {
            let mut end = index + ch.len_utf8();
            markers.push((index, end));
            if mode == Markers::Space {
                push_decoded(&mut text, &mut bounds, &mut hidden, " ", (index, end));
                index = end;
                continue;
            }
            hidden.get_or_insert(index);
            if ch == PLACEHOLDER_OPEN && mode == Markers::Drop {
                if next_close.is_none_or(|close| close.is_some_and(|at| at < end)) {
                    next_close = Some(source[end..].find(PLACEHOLDER_CLOSE).map(|at| end + at));
                }
                if let Some(Some(close)) = next_close {
                    dropped_body = true;
                    end = close + PLACEHOLDER_CLOSE.len_utf8();
                }
            }
            markers.last_mut().expect("just pushed").1 = end;
            index = end;
            continue;
        }
        // Percent run inside a URL token.
        if ch == '%' && (in_url || escape.is_some()) {
            let run_end = percent_run_end(source, index).max(index + 1);
            let (decoded, _) = decode_percent_run(&source[index..run_end]);
            push_decoded(
                &mut text,
                &mut bounds,
                &mut hidden,
                &decoded,
                (index, run_end),
            );
            index = run_end;
            continue;
        }
        // Named or numeric HTML entity.
        if ch == '&' {
            if let Some((decoded, consumed)) = decode_entity(source, index) {
                let end = index + consumed;
                push_decoded(&mut text, &mut bounds, &mut hidden, &decoded, (index, end));
                index = end;
                continue;
            }
        }
        let end = index + ch.len_utf8();
        push_decoded(
            &mut text,
            &mut bounds,
            &mut hidden,
            ch.encode_utf8(&mut [0; 4]),
            (index, end),
        );
        index = end;
    }
    // Dropped bytes at the end belong to the last kept character.
    if let (Some(_), Some(last)) = (hidden, bounds.last_mut()) {
        last.1 = source.len();
    }
    (text, bounds, dropped_body, markers)
}

/// Append `value` to the decoded view, attributing each char to `bound`. A
/// default-ignorable char (zero-width space, soft hyphen) is dropped; its bytes
/// go to the next kept char.
fn push_decoded(
    text: &mut String,
    bounds: &mut Vec<(usize, usize)>,
    hidden: &mut Option<usize>,
    value: &str,
    bound: (usize, usize),
) {
    for ch in value.chars() {
        if crate::contacts::fold::is_default_ignorable(ch) {
            hidden.get_or_insert(bound.0);
            continue;
        }
        text.push(ch);
        bounds.push((
            hidden.take().map_or(bound.0, |start| start.min(bound.0)),
            bound.1,
        ));
    }
}

/// The byte ranges of every whitespace-delimited token that carries a URL
/// scheme (`://`).
pub fn url_ranges(source: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let start = index;
        let mut end = index;
        while end < bytes.len()
            && !bytes[end].is_ascii_whitespace()
            && !matches!(bytes[end], b'<' | b'>' | b'"' | b'\'' | b')' | b'(')
        {
            end += 1;
        }
        if source[start..end].contains("://") {
            ranges.push((start, end));
        }
        index = end.max(index + 1);
    }
    ranges
}
