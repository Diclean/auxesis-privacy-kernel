//! The linear secret-link scan and its span merge.

use super::layout::{line_table, Pairs};
use super::lex::{bounded, fold};
use super::link::{link, weak_counts};
use super::table::{columns, continuations, pipe_value};
use super::{Kind, Line, Shape, FLOOR, KEY_RE, WEAK};

/// The value spans of every linked key in `text`, one per physical line, sorted.
/// Original offsets; `text` is read as it is (no view drops a character).
pub(crate) fn link_scan(text: &str) -> Vec<(usize, usize)> {
    scan(text, true)
}

/// `link_scan`, with the table spans of PR2 only when `tables` is set: they are
/// only added, so the spans without them are a subset (P4).
pub(super) fn scan(text: &str, tables: bool) -> Vec<(usize, usize)> {
    let (folded, map, ascii) = folded_text(text);
    // Most texts hold no key: they skip the line table.
    if !KEY_RE.is_match(&folded) {
        return Vec::new();
    }
    let original = |at: usize| if ascii { at } else { map[at] };
    let (lines, pairs) = line_table(text);
    let tail = text.trim_end().len();
    let (mut spans, mut cells, mut upto) =
        scan_keys(text, &folded, original, &lines, &pairs, tail, tables);
    cells = table_spans(text, &lines, cells, tables);
    let (openers, closes) = &pairs;
    spans = mask_cells(spans, cells, closes, openers, tail, &mut upto);
    opener_spans(text, &lines, openers, &upto, spans)
}

/// Fold `text` and map every folded byte back to its original offset. `ascii`
/// says whether the folded text is the original, byte for byte.
fn folded_text(text: &str) -> (String, Vec<usize>, bool) {
    let (mut folded, mut map, ascii) = (String::new(), Vec::new(), text.is_ascii());
    if ascii {
        let space = |byte: u8| {
            if matches!(byte, b'-' | b'_') {
                b' '
            } else {
                byte
            }
        };
        folded = text
            .bytes()
            .map(|byte| char::from(space(byte).to_ascii_lowercase()))
            .collect();
    } else {
        for (at, ch) in text.char_indices() {
            let before = folded.len();
            fold(ch, &mut folded);
            map.resize(map.len() + folded.len() - before, at);
        }
    }
    map.push(text.len());
    (folded, map, ascii)
}

/// A key scan's value spans, the table cells it saw and its opener stops.
type KeyScan = (Vec<(usize, usize)>, Vec<(usize, usize)>, Vec<usize>);

/// Scan every linked key: return its value spans, the table cells and the
/// opener stops the value scan found.
fn scan_keys(
    text: &str,
    folded: &str,
    original: impl Fn(usize) -> usize,
    lines: &[Line],
    pairs: &Pairs,
    tail: usize,
    tables: bool,
) -> KeyScan {
    let (openers, closes) = pairs;
    let (mut spans, mut reach, mut index, mut cells) = (Vec::new(), 0, 0, Vec::new());
    let (mut nested_tails, mut nested_reach) = (Vec::new(), 0);
    let mut cursor = 0;
    let mut upto = vec![0; openers.len()];
    for found in KEY_RE.find_iter(folded) {
        let Some(key_end) = bounded(folded, found.start(), found.end()) else {
            continue;
        };
        let (start, end) = (original(found.start()), original(key_end));
        while lines[index].end < start {
            index += 1;
        }
        let line = &lines[index];
        let code_pin = found.as_str().starts_with("code ") && found.as_str().ends_with("pin");
        let weak = WEAK.contains(&found.as_str()) || code_pin;
        let reference_cue = (matches!(
            found.as_str(),
            "secret" | "secrets" | "token" | "tokens" | "pin" | "pins" | "jeton" | "jetons"
        ) || code_pin)
            && line.config
            && matches!(line.shape, Shape::Entry(_, _, key) if start >= key.1);
        if weak && !reference_cue && !weak_counts(text, line, start, end) {
            continue;
        }
        if tables {
            cells.extend(pipe_value(text, end, line.end));
        }
        if start < reach {
            continue;
        }
        let Some(linked) = link(text, end, line.end) else {
            continue;
        };
        // A block header (with no comment, or in config): the value is the block, not
        // `|`, which would be the residue view's value once the block is masked.
        let from = match line.shape {
            Shape::Entry(_, Kind::Header, key)
                if key.0 <= start
                    && end <= key.1
                    && (line.config || !text[linked..line.end].contains('#')) =>
            {
                line.end
            }
            _ => linked,
        };
        let value_end = line.value_end;
        reach = value_end;
        let Some(value) = text[from..value_end].find(|ch: char| !ch.is_whitespace()) else {
            continue;
        };
        let value = from + value;
        let (mut pieces, mut chars) = (Vec::new(), 0);
        for line in lines[index..]
            .iter()
            .take_while(|line| line.start < value_end)
        {
            if line.end <= value {
                continue;
            }
            let piece = &text[line.start.max(value)..line.end.min(value_end)];
            let trimmed = piece.trim();
            if !trimmed.is_empty() {
                let at = line.start.max(value) + piece.len() - piece.trim_start().len();
                pieces.push((at, at + trimmed.len()));
                chars += trimmed.chars().filter(|ch| !ch.is_whitespace()).count();
            }
        }
        if chars >= FLOOR {
            // Opener mask: an opener before the value whose closer it masks.
            let last = pieces.last().map_or(0, |piece| piece.1);
            while closes.get(cursor).is_some_and(|close| close.0 < value_end) {
                let (close, id) = closes[cursor];
                if close >= value && openers[id].0 < value && last < tail {
                    upto[id] = value;
                }
                cursor += 1;
            }
            spans.extend(pieces);
            // A prose cue inside another entry's value (e.g. `Ref: password is`)
            // can be followed by a passphrase word that looks like a config key.
            // Keep the config reading above and also mask to the paragraph end.
            if line.config
                && matches!(line.shape, Shape::Entry(_, _, key) if start >= key.1)
                && line.paragraph_end > line.value_end.max(nested_reach)
            {
                for part in lines[index + 1..]
                    .iter()
                    .take_while(|part| part.start < line.paragraph_end)
                {
                    let from = part.start.max(line.value_end).max(nested_reach);
                    if from >= part.end {
                        continue;
                    }
                    let text_part = &text[from..part.end];
                    let trimmed = text_part.trim();
                    if !trimmed.is_empty() {
                        let at = from + text_part.len() - text_part.trim_start().len();
                        nested_tails.push((at, at + trimmed.len()));
                    }
                }
                nested_reach = line.paragraph_end;
            }
        }
    }
    spans = union(spans, nested_tails);
    (spans, cells, upto)
}

/// Add the table spans when `tables` is on: its cells, then their continuations.
fn table_spans(
    text: &str,
    lines: &[Line],
    mut cells: Vec<(usize, usize)>,
    tables: bool,
) -> Vec<(usize, usize)> {
    if tables {
        let mut table = Vec::new();
        columns(text, lines, &mut cells, &mut table);
        cells = union(cells, table);
        let owned = continuations(text, lines, &cells);
        cells = union(cells, owned);
    }
    cells
}

/// Opener-mask the cells: a closer inside a cell, its opener before it.
fn mask_cells(
    mut spans: Vec<(usize, usize)>,
    cells: Vec<(usize, usize)>,
    closes: &[(usize, usize)],
    openers: &[(usize, usize)],
    tail: usize,
    upto: &mut [usize],
) -> Vec<(usize, usize)> {
    if !cells.is_empty() {
        // Opener mask for a cell: a closer inside it, its opener before it.
        let mut next = 0;
        for &(close, id) in closes {
            while cells.get(next).is_some_and(|cell| cell.1 <= close) {
                next += 1;
            }
            if let Some(&(start, end)) = cells.get(next) {
                if start <= close && openers[id].0 < start && end < tail {
                    upto[id] = upto[id].max(start);
                }
            }
        }
        spans = union(spans, cells);
    }
    spans
}

/// Mask every line of a flagged opener up to its value.
fn opener_spans(
    text: &str,
    lines: &[Line],
    openers: &[(usize, usize)],
    upto: &[usize],
    spans: Vec<(usize, usize)>,
) -> Vec<(usize, usize)> {
    // A flagged opener on an earlier line than its value (a fence, a multi-line quote)
    // is masked with every line up to the value: once the opener is masked, the
    // residue view would read that content (quotes inside a fence, a fence inside a
    // quote) as live structure.
    // Openers come in text order: one line cursor finds each opener's line, so a
    // same-line check is one comparison, not a rescan (N5: nested openers).
    let (mut extra, mut covered, mut row) = (Vec::new(), 0, 0);
    for (&(start, end), &upto) in openers.iter().zip(upto) {
        if upto == 0 || start < covered {
            continue;
        }
        while lines[row].end < end {
            row += 1;
        }
        // The line's `\n` sits at its end; the last line has none.
        if lines[row].end >= upto {
            extra.push((start, end));
            continue;
        }
        let mut at = start;
        for part in text[start..upto].split('\n') {
            let trimmed = part.trim();
            let lead = at + part.len() - part.trim_start().len();
            if !trimmed.is_empty() {
                extra.push((lead, lead + trimmed.len()));
            }
            at += part.len() + 1;
        }
        covered = upto;
    }
    union(extra, spans)
}

/// Two runs of spans, each sorted by start, merged in one pass (D6: no sort); spans
/// that overlap or touch join.
fn union(a: Vec<(usize, usize)>, b: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    debug_assert!(a.is_sorted_by_key(|span| span.0) && b.is_sorted_by_key(|span| span.0));
    let mut merged = Vec::<(usize, usize)>::with_capacity(a.len() + b.len());
    let (mut a, mut b) = (a.into_iter().peekable(), b.into_iter().peekable());
    while let Some(span) = match (a.peek(), b.peek()) {
        (Some(x), Some(y)) if x.0 < y.0 => a.next(),
        (_, Some(_)) => b.next(),
        _ => a.next(),
    } {
        match merged.last_mut().filter(|last| span.0 <= last.1) {
            Some(last) => last.1 = last.1.max(span.1),
            None => merged.push(span),
        }
    }
    merged
}
