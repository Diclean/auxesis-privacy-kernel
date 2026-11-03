//! The table scan: header lines, capped rows and quote-aware records.

use super::header::{header, secret_header, Names, Table};
use super::rows::{heading, names, prose, row_cells, verdict, whole};
use super::scan::trimmed;

/// Rows of one table read under its header by the capped passes.
const MAX_ROWS: usize = 10_000;

/// Hides the secret cells of every table and returns its header lines. Rows
/// are read twice: a line at a time, and as CSV records whose quoted cells may
/// hold line breaks, so a record never hides less than its lines. Each is read
/// again `wide`: no row cap (SECRET-LEAK-294B: filler rows pushed a password
/// past [`MAX_ROWS`]), the wider header list, and a table kept across blank
/// lines (SECRET-FR-HDR-1); its spans only add, its header lines are not kept.
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

/// The secret cells of every table the export list names (a bare `pass`, the
/// password manager columns), read like the wide pair of [`columns`]. Not a
/// part of [`lines_scan`](super::scan::lines_scan): the gate adds these spans on top of what main's
/// scans and residue rounds already hide, so they can only hide more
/// (SECRET-LEAK-294B).
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
