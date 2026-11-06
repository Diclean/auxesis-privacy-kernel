//! The table scan: header lines, capped rows and quote-aware records.

use super::header::{cells, header, header_of, secret_header, Names, Table, DELIMS};
use super::rows::{heading, names, prose, row_cells, verdict, whole};
use super::scan::trimmed;

/// The most shapes of open tables [`secret_table_lines`] keeps: past them a
/// table no longer ends, so the pass stays linear.
const MAX_SHAPES: usize = 16;

/// Rows of one table read under its header by the capped passes.
const MAX_ROWS: usize = 10_000;

/// Hides the secret cells of every table and returns its header lines. Rows
/// are read twice: a line at a time, and as CSV records whose quoted cells may
/// hold line breaks, so a record never hides less than its lines. Each is read
/// again `wide`: no row cap (filler rows pushed a password
/// past [`MAX_ROWS`]), the wider header list, and a table kept across blank
/// lines; its spans only add, its header lines are not kept.
pub(super) fn columns(text: &str, spans: &mut Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    let mut headers = Vec::new();
    // A header needs two cells: with no delimiter there is no table to read.
    if !text.bytes().any(|b| b",\t;|".contains(&b)) {
        return headers;
    }
    tables(text, false, Names::Main, spans, &mut headers);
    tables(text, true, Names::Main, spans, &mut headers);
    tables(text, false, Names::Wide, spans, &mut Vec::new());
    tables(text, true, Names::Wide, spans, &mut Vec::new());
    headers.sort_unstable();
    headers.dedup();
    headers
}

/// The stretches of `text`, up to the line holding `last`, that lie in a table
/// under a header naming a secret column under any list, each from its header
/// line on. A table ends at a line with text, outside quotes and with no
/// quote and none of the sorted `kept` ranges (a stand-in may hide a line
/// break), that fits none of the open tables' shapes: blank and quoted lines
/// keep it, so it ends no sooner than the scans end it. One pass, one
/// [`cells`] pass per delimiter for a header line.
pub(crate) fn secret_table_lines(
    text: &str,
    last: usize,
    kept: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    table_lines(text, last, kept, &mut 0)
}

/// [`secret_table_lines`], counting in `work` each open shape read.
pub(super) fn table_lines(
    text: &str,
    last: usize,
    kept: &[(usize, usize)],
    work: &mut usize,
) -> Vec<(usize, usize)> {
    let (mut lines, mut open, mut quoted, mut at) = (Vec::new(), Vec::<Table>::new(), false, 0);
    if !text.bytes().any(|b| DELIMS.contains(&b)) {
        return lines;
    }
    let (bytes, mut unsure, mut closes) = (text.as_bytes(), false, false);
    // The line a lookahead from a mark stopped on, and whether it is odd.
    let mut ahead = (0, false);
    while at <= last.min(text.len()) {
        let next = memchr_nl(bytes, at);
        let end = next - usize::from(text[..next].ends_with('\r'));
        let line = &text[at..end];
        let fits = |open: &Table| row_cells(text, at, end, open).len() == open.count;
        // Past [`MAX_SHAPES`] a table no longer ends, so no more are kept.
        let mark = kept
            .get(kept.partition_point(|k| k.1 <= at))
            .is_some_and(|k| k.0 <= end);
        // With no odd line anywhere ahead no later line closes a quote the
        // mark hid, so the record ends on the mark's line, as the whole
        // text's record scan ends it: the hold ends at prose (no quote, no
        // delimiter). While an odd line lies ahead it holds to it, as main.
        // Safe only while [`tables`] ends a table at a row with no delimiter
        // (`broken` there): if it kept one, prose would be a row to hide.
        let prose = !mark && !line.contains('"') && !line.bytes().any(|b| DELIMS.contains(&b));
        if unsure && !closes && prose {
            unsure = false;
        }
        let plain = !quoted && !unsure && !mark && !line.contains('"');
        let ends = plain && !line.trim().is_empty() && open.len() < MAX_SHAPES;
        if ends && !open.iter().inspect(|_| *work += 1).any(fits) {
            open.clear();
        }
        // A mark on a line that fits no open shape may hide the quote that
        // opened a record over lines: the table holds to a line with an odd
        // number of quotes, which may close it.
        if mark && !open.is_empty() && !open.iter().inspect(|_| *work += 1).any(fits) {
            if ahead.0 <= next {
                ahead = odd_ahead(bytes, next + 1);
            }
            (unsure, closes) = (true, ahead.1);
        } else if odd(bytes, at, end) {
            unsure = false;
        }
        let mut heads = Vec::new();
        if line.bytes().any(|b| DELIMS.contains(&b)) {
            for (delim, row) in DELIMS.map(|delim| (delim, cells(text, at, end, delim))) {
                for names in [Names::Main, Names::Wide, Names::Export] {
                    heads.extend(header_of(text, (at, end), names, delim, &row));
                }
            }
        }
        quoted = heads.is_empty() && !open.is_empty() && quoted != odd(bytes, at, end);
        for head in heads {
            let same =
                |t: &Table| (t.delim, t.count, t.loose) == (head.delim, head.count, head.loose);
            if open.len() < MAX_SHAPES && !open.iter().inspect(|_| *work += 1).any(same) {
                open.push(head);
            }
        }
        if !open.is_empty() {
            match lines.last_mut() {
                Some(stretch) if stretch.1 + 1 >= at => stretch.1 = next,
                _ => lines.push((at, next)),
            }
        }
        at = next + 1;
    }
    lines
}

/// The secret cells of every table the export list names (a bare `pass`, the
/// password manager columns), read like the wide pair of [`columns`]. Not a
/// part of [`lines_scan`](super::scan::lines_scan): the gate adds these spans on top of what main's
/// scans and residue rounds already hide, so they can only hide more
/// more.
pub(crate) fn export_scan(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    if text.bytes().any(|b| b",\t;|".contains(&b)) {
        tables(text, false, Names::Export, &mut spans, &mut Vec::new());
        tables(text, true, Names::Export, &mut spans, &mut Vec::new());
    }
    spans.sort_unstable();
    spans.dedup();
    spans
}

/// The end of the record at `at`: its line end, or with `records` the end of
/// the line that closes a quote the record opens, however far; its line end
/// when no line closes it. Linear over a table: a scan from a line
/// with an odd quote count stops at the next such line, and when none closes
/// it every later line is even and never scans.
fn record_end(text: &str, at: usize, records: bool) -> usize {
    let bytes = text.as_bytes();
    let first = memchr_nl(bytes, at);
    let mut open = records && odd(bytes, at, first);
    let mut end = first;
    while open && end < bytes.len() {
        let next = memchr_nl(bytes, end + 1);
        open ^= odd(bytes, end + 1, next);
        end = next;
    }
    if open {
        first
    } else {
        end
    }
}

/// The start of the first line from `from` with an odd number of quotes
/// (`true`), or the text end (`false`). Blank lines do not stop it: a quoted
/// cell may hold them, and the odd line after them may close it. Each byte is
/// read once over a pass: the caller asks again only past the line found, and
/// never once none is found.
fn odd_ahead(bytes: &[u8], mut from: usize) -> (usize, bool) {
    while from < bytes.len() {
        let next = memchr_nl(bytes, from);
        if odd(bytes, from, next) {
            return (from, true);
        }
        from = next + 1;
    }
    (bytes.len(), false)
}

/// The next line break at or after `from`, or the text end.
fn memchr_nl(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |n| from + n)
}

/// Whether `bytes[from..to]` holds an odd number of quotes.
fn odd(bytes: &[u8], from: usize, to: usize) -> bool {
    bytes[from..to].iter().filter(|&&b| b == b'"').count() % 2 == 1
}

fn tables(
    text: &str,
    records: bool,
    list: Names,
    spans: &mut Vec<(usize, usize)>,
    headers: &mut Vec<(usize, usize)>,
) {
    let wide = list.wide();
    let max_rows = if wide { usize::MAX } else { MAX_ROWS };
    let no_cr = |next: usize| next - usize::from(text[..next].ends_with('\r'));
    let mut table: Option<Table> = None;
    let (mut at, mut quoted_break) = (0, false);
    while at < text.len() {
        let after_break = std::mem::take(&mut quoted_break);
        let mut next = record_end(text, at, records && table.is_some());
        let end = no_cr(next);
        if let Some(open) = table.as_mut().filter(|_| wide) {
            // A blank line after a row keeps the table; the next line goes on
            // with it only when it has the table's shape and is neither a
            // header nor prose. Right under the header it closes the table, as
            // the residue view ends a masked header cell's line there.
            if text[at..end].trim().is_empty() && open.rows > 0 {
                (open.gap, quoted_break) = (true, after_break);
                at = next + 1;
                continue;
            }
            if std::mem::take(&mut open.gap) {
                // A header with a value cell (`7,token,Paris`) is a row.
                let row = row_cells(text, at, end, open);
                if row.len() != open.count
                    || header(text, at, end, list).is_some() && names(text, &row)
                    || heading(text, at, end, open)
                    || prose(text, at, end, open)
                {
                    table = None;
                }
            }
        }
        let width = table.as_ref().map(|open| open.count);
        if table.as_ref().is_some_and(|open| open.broke) && header(text, at, end, list).is_some() {
            table = None;
        }
        if let Some(open) = table.as_mut() {
            open.broke = false;
            let row = row_cells(text, at, end, open);
            let broken = row.len() != open.count && !text[at..end].trim().is_empty();
            if broken && text[at..end].contains('"') && open.rows < max_rows {
                // A quoted row that breaks the table hides where the secret
                // column is, its quote closed or not: it goes whole, and the
                // rows after it still belong to the table unless it heads one.
                (open.rows, open.broke, quoted_break) = (open.rows + 1, true, true);
                whole(text, at, end, spans);
                if header(text, at, no_cr(record_end(text, at, false)), list).is_some() {
                    table = None;
                }
            } else if broken || text[at..end].trim().is_empty() || open.rows >= max_rows {
                table = None;
            } else {
                open.rows += 1;
                // A row that names a secret in another column opens a new
                // table of the same width; its columns add to the old ones.
                // Its cell under an old secret column is still hidden, even a
                // secret name: `alice,secret,token` is a password `secret`.
                let new = header(text, at, end, list)
                    .filter(|new| new.delim == open.delim && new.secret != open.secret);
                if new.is_some() && !names(text, &row) {
                    // A secret name beside a value is no header: the row goes.
                    whole(text, at, end, spans);
                }
                // Only a row made of rule cells (`|---|:--|`) is a divider.
                let divider = row.iter().all(|&(s, e)| {
                    let (s, e) = trimmed(text, s, e);
                    text[s..e].bytes().all(|b| b"-:= ".contains(&b))
                });
                let mut hidden: Vec<(usize, usize)> = Vec::new();
                let mut tail = 0;
                for &column in &open.secret {
                    let raw = &text[row[column].0..row[column].1];
                    let (mut start, mut stop) = trimmed(text, row[column].0, row[column].1);
                    if !records {
                        // A line keeps a cell's quotes, so none stays clear.
                        start = row[column].0 + raw.len() - raw.trim_start().len();
                        stop = start.max(row[column].0 + raw.trim_end().len());
                    } else {
                        // A record's value drops the blanks inside its quotes
                        // too, as the residue view ends each stand-in with a
                        // line break; a value that still holds one keeps its
                        // quotes.
                        let (inner, last) = trimmed(text, start, stop);
                        if text[inner..last].contains('\n') {
                            start = row[column].0 + raw.len() - raw.trim_start().len();
                            stop = row[column].0 + raw.trim_end().len();
                        } else {
                            (start, stop) = (inner, last);
                        }
                    }
                    let cell = &text[start..stop];
                    if cell.is_empty() || divider || start < tail {
                        continue;
                    }
                    if open.verdict.binary_search(&column).is_ok() && verdict(cell) {
                        continue;
                    }
                    if secret_header(cell, list) || open.tail {
                        // A secret name as a value (`alice,secret,token`): its
                        // whole line goes, the password beside it too; one
                        // line per row keeps it linear.
                        let line = memchr_nl(text.as_bytes(), start).min(end);
                        tail = start + text[start..line].trim_end().len();
                        stop = tail.max(stop);
                        start = text[at..start].rfind('\n').map_or(at, |n| at + n + 1);
                    }
                    // Cells apart only by delimiters, blanks, quotes or secret
                    // names are one span: nothing between two values is clear.
                    let gap = |from: usize| {
                        text[from..start]
                            .split(char::from(open.delim))
                            .all(|piece| {
                                let piece = piece.trim().trim_matches('"');
                                piece.is_empty() || secret_header(piece, list)
                            })
                    };
                    match hidden.last_mut() {
                        Some(prev) if prev.1 <= start && gap(prev.1) => prev.1 = stop,
                        _ => hidden.push((start, stop)),
                    }
                }
                // A record over several lines is hidden from its first secret
                // cell to its last, so no stand-in splits it.
                match (hidden.first(), hidden.last()) {
                    (Some(&(start, _)), Some(&(_, stop))) if text[at..end].contains('\n') => {
                        spans.push((start, stop));
                    }
                    _ => spans.extend(hidden),
                }
                if let Some(mut new) = new {
                    // A column either header names from the older lists is
                    // no export column, and has no verdicts.
                    let older = |table: &Table, column: usize| {
                        table.secret.binary_search(&column).is_ok()
                            && table.extra.binary_search(&column).is_err()
                    };
                    let joined = |a: &[usize], b: &[usize]| {
                        let mut out: Vec<usize> = a
                            .iter()
                            .chain(b)
                            .copied()
                            .filter(|&column| !older(&new, column) && !older(open, column))
                            .collect();
                        out.sort_unstable();
                        out.dedup();
                        out
                    };
                    let extra = joined(&new.extra, &open.extra);
                    let verdict = joined(&new.verdict, &open.verdict);
                    (new.extra, new.verdict) = (extra, verdict);
                    new.secret.extend(open.secret.iter().copied());
                    new.secret.sort_unstable();
                    new.secret.dedup();
                    headers.push((at, end));
                    *open = new;
                }
            }
        }
        if table.is_none() {
            next = record_end(text, at, false);
            let end = no_cr(next);
            table = header(text, at, end, list);
            if table.is_some() {
                headers.push((at, end));
                if after_break || table.as_ref().map(|open| open.count) == width {
                    // A header of the same width right under a secret table's
                    // rows, or right after a broken quoted row, may be a row
                    // of secret names: it goes whole.
                    whole(text, at, end, spans);
                }
            }
        }
        at = next + 1;
    }
}
