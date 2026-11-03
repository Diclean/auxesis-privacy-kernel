//! Table cells and column scanning for the secret-link scanner.

use super::lex::{is_mark, secret_key};
use super::{Line, Shape, FLOOR};

/// Split `text[from..to]` at each unescaped `|`; `cell(start, end, last)` gets each
/// cell in order and returns false to stop.
fn split(text: &str, from: usize, to: usize, mut cell: impl FnMut(usize, usize, bool) -> bool) {
    let (mut at, mut escaped) = (from, false);
    for (i, &byte) in text.as_bytes()[from..to].iter().enumerate() {
        if byte == b'|' && !escaped {
            if !cell(at, from + i, false) {
                return;
            }
            at = from + i + 1;
        }
        escaped = byte == b'\\' && !escaped;
    }
    cell(at, to, true);
}

/// The cells of a table line: the indent and one leading `|` skipped, a last
/// blank cell after a final `|` dropped.
fn row(text: &str, line: &Line, mut cell: impl FnMut(usize, usize) -> bool) {
    let from = line.indent + usize::from(text[line.indent..line.end].starts_with('|'));
    split(text, from, line.end, |start, end, last| {
        let blank = text[start..end].trim().is_empty();
        last && blank && text[..start].ends_with('|') || cell(start, end)
    });
}

/// The trimmed cell `text[start..end]`, if it has `floor` non-whitespace chars.
fn cell_value(text: &str, start: usize, end: usize, floor: usize) -> Option<(usize, usize)> {
    let cell = &text[start..end];
    let (at, trimmed) = (start + cell.len() - cell.trim_start().len(), cell.trim());
    let chars = trimmed.chars().filter(|ch| !ch.is_whitespace()).count();
    (chars >= floor).then_some((at, at + trimmed.len()))
}

/// The `|` link: a key followed (past its marks) by `|` links to the next
/// non-blank cell on its line, which ends at the next unescaped `|` or the line end.
pub(super) fn pipe_value(text: &str, key_end: usize, line_end: usize) -> Option<(usize, usize)> {
    let mut at = key_end;
    for _ in 0..4 {
        match text[at..line_end].chars().next() {
            Some(ch) if is_mark(ch) => at += ch.len_utf8(),
            _ => break,
        }
    }
    let at = line_end - text[at..line_end].trim_start_matches([' ', '\t']).len();
    if !text[at..line_end].starts_with('|') {
        return None;
    }
    let mut value = None;
    split(text, at + 1, line_end, |start, end, _| {
        let blank = text[start..end].trim().is_empty();
        value = if blank {
            None
        } else {
            cell_value(text, start, end, FLOOR)
        };
        blank
    });
    value
}

/// The cell count of a valid delimiter line: every cell `[ \t]*:?-+:?[ \t]*`.
/// Whether it holds a `|` too: a pipe-free one (one cell, `---`) needs a header with
/// a `|`, so a heading rule under a plain line is no table.
fn delimiter(text: &str, line: &Line) -> Option<(usize, bool)> {
    let (mut count, mut valid) = (0, true);
    row(text, line, |start, end| {
        let cell = text[start..end].trim_matches([' ', '\t', '\r']);
        let cell = cell.strip_prefix(':').unwrap_or(cell);
        let cell = cell.strip_suffix(':').unwrap_or(cell);
        (count, valid) = (
            count + 1,
            !cell.is_empty() && cell.bytes().all(|b| b == b'-'),
        );
        valid
    });
    valid.then_some((count, text[line.start..line.end].contains('|')))
}

/// The owned lines right after each cell's line (PR1b ownership), masked whole,
/// one trimmed piece per line. A cell that masks an opener (a quote, a key, a block
/// header) ends that ownership in the residue view, which would read the lines as
/// rows. `cells` is sorted by start, so the line cursor and the result are too, and
/// each line is read once.
pub(super) fn continuations(
    text: &str,
    lines: &[Line],
    cells: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let (mut owned, mut row, mut free) = (Vec::new(), 0, 0);
    for &(start, _) in cells {
        while lines[row].end < start {
            row += 1;
        }
        let mut next = free.max(row + 1);
        while lines.get(next).is_some_and(|line| line.joined) {
            let piece = &text[lines[next].start..lines[next].end];
            let at = lines[next].start + piece.len() - piece.trim_start().len();
            if !piece.trim().is_empty() {
                owned.push((at, at + piece.trim().len()));
            }
            next += 1;
        }
        free = next;
    }
    owned
}

/// The column form: each cell under a key column of a table outside every fence
/// and owned region. A table is a header line right above a delimiter with as many
/// cells (else no table, D5); its run of lines ends at a blank, owned or fence line.
/// Each line is read once as a delimiter, once as a header and once as a row, never
/// over the header's columns (#156 r3: a quadratic table scan). `pipes`: the
/// `|`-link values, in text order.
///
/// The gate ends each stand-in's line, so the residue view can read a table the first
/// pass did not have. Three rules keep it from finding a clear value there:
/// - a header inside a run adds its key columns to the run's: if the outer header is
///   masked away, the inner table still masks what the residue view would read;
/// - after a masked value, the rest of a row reads as a new row from column 0
///   (`after`), and a cell under a key column in either count is masked, with no
///   floor (a short cell can merge with a masked value next to it);
/// - right above a delimiter, the last `|`-link value runs to the line end, so the
///   rest of that line never reads as a header.
pub(super) fn columns(
    text: &str,
    lines: &[Line],
    pipes: &mut [(usize, usize)],
    out: &mut Vec<(usize, usize)>,
) {
    let usable = |line: &Line| !line.joined && !matches!(line.shape, Shape::Blank | Shape::Fence);
    let (mut keys, mut any, mut pending, mut pipe) = (Vec::new(), false, None::<Vec<bool>>, 0);
    for (i, line) in lines.iter().enumerate() {
        if !usable(line) {
            (keys, any, pending) = (Vec::new(), false, None);
            continue;
        }
        while pipes.get(pipe).is_some_and(|value| value.0 < line.start) {
            pipe += 1;
        }
        let mut to = pipe;
        while pipes.get(to).is_some_and(|value| value.0 < line.end) {
            to += 1;
        }
        let below = lines
            .get(i + 1)
            .filter(|next| usable(next))
            .and_then(|next| delimiter(text, next));
        if below.is_some() && to > pipe {
            pipes[to - 1].1 = line.start + text[line.start..line.end].trim_end().len();
        }
        if any {
            let (mut column, mut after, mut next) = (0, 0, pipe);
            row(text, line, |start, end| {
                let key = |column: usize| keys.get(column) == Some(&true);
                let mut masked = None;
                if next < to && pipes[next].0 < end {
                    (masked, next) = (Some(pipes[next].1), next + 1);
                }
                if let Some(value) = (key(column) || key(after))
                    .then(|| cell_value(text, start, end, 1))
                    .flatten()
                {
                    (_, masked) = (out.push(value), masked.max(Some(value.1)));
                }
                after = match masked {
                    Some(at) if at <= end => {
                        usize::from(!text[at..end].trim_matches([' ', '\t']).is_empty())
                    }
                    _ => after + 1,
                };
                column += 1;
                true
            });
        }
        if let Some(header) = pending.take() {
            for (column, key) in header.into_iter().enumerate() {
                match keys.get_mut(column) {
                    Some(old) => *old |= key,
                    None => keys.push(key),
                }
                any |= key;
            }
        }
        if let Some((count, _)) =
            below.filter(|&(_, piped)| piped || text[line.start..line.end].contains('|'))
        {
            let mut header = Vec::new();
            row(text, line, |start, end| {
                header.push(secret_key(&text[start..end]));
                header.len() <= count
            });
            pending = (header.len() == count).then_some(header);
        }
    }
}
