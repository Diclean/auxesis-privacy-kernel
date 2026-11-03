//! Row cells and the decisions that read a row as prose, a header or a value.

use super::header::{cells, Table};

/// A pass/fail cell (`yes`, `fail`, `✓`): under a bare `pass` header it is a
/// result, not a password.
pub(super) fn verdict(cell: &str) -> bool {
    [
        "yes", "no", "y", "n", "true", "false", "pass", "passed", "fail", "failed", "ok", "oui",
        "non", "x", "0", "1", "error", "skip", "skipped", "pending", "na", "n/a", "none", "✓", "✗",
        "✔", "✘",
    ]
    .contains(&cell.trim().trim_matches('"').trim().to_lowercase().as_str())
}

/// A line that reads as a header of any table: every cell a name, or a cell
/// that is a cell of `open`'s header (`id,name,city` under `id,password,city`).
pub(super) fn heading(text: &str, at: usize, end: usize, open: &Table) -> bool {
    let cell = |(s, e): (usize, usize)| text[s..e].trim().trim_matches('"').to_lowercase();
    let row: Vec<String> = cells(text, at, end, open.delim)
        .into_iter()
        .map(cell)
        .collect();
    let named = row.iter().all(|cell| {
        cell.chars().any(char::is_alphabetic)
            && cell
                .chars()
                .all(|ch| ch.is_alphabetic() || " _-".contains(ch))
    });
    // A set, so a wide row is matched in one pass (a header of n cells and a
    // row of n cells cost n lookups, not n²).
    let head: std::collections::HashSet<String> = cells(text, open.head.0, open.head.1, open.delim)
        .into_iter()
        .map(cell)
        .collect();
    named
        || row
            .iter()
            .any(|cell| !cell.is_empty() && head.contains(cell))
}

/// The cells of a row of `open`, a blank last cell past its width dropped
/// (`7,pw,Paris,`), so a trailing delimiter does not break the table; under a
/// header that ends with a blank cell, an unquoted row one cell short gets it
/// empty.
pub(super) fn row_cells(text: &str, at: usize, end: usize, open: &Table) -> Vec<(usize, usize)> {
    let mut row = cells(text, at, end, open.delim);
    // A quoted row keeps main's reading: one cell short, it goes whole.
    if open.loose && row.len() + 1 == open.count && !text[at..end].contains('"') {
        row.push((end, end));
    }
    if row.len() == open.count + 1
        && row
            .last()
            .is_some_and(|&(s, e)| text[s..e].trim().is_empty())
    {
        row.pop();
    }
    row
}

/// A line that reads as a sentence: four words or more, with a blank after
/// each delimiter (`Thanks, see you, Bob`), or ending `.`, `!` or `?` with four
/// words outside `open`'s secret cells (`2,violet tractor humming seventy.` is
/// a passphrase row).
pub(super) fn prose(text: &str, at: usize, end: usize, open: &Table) -> bool {
    let line = text[at..end].trim().trim_end_matches('"');
    if line.split_whitespace().count() < 4 {
        return false;
    }
    let spaced = line
        .as_bytes()
        .windows(2)
        .all(|pair| pair[0] != open.delim || pair[1] == b' ');
    if spaced {
        return true;
    }
    if !line.ends_with(['.', '!', '?']) {
        return false;
    }
    // `secret` is sorted, so a wide row costs cells × log(columns), not cells².
    let outside: usize = cells(text, at, end, open.delim)
        .iter()
        .enumerate()
        .filter(|(column, _)| open.secret.binary_search(column).is_err())
        .map(|(_, &(s, e))| text[s..e].split_whitespace().count())
        .sum();
    outside >= 4
}

/// Whether every cell of `row` reads as a column name or is blank.
pub(super) fn names(text: &str, row: &[(usize, usize)]) -> bool {
    row.iter().all(|&(s, e)| {
        let cell = text[s..e].trim().trim_matches('"');
        cell.chars()
            .all(|ch| ch.is_alphabetic() || " _-".contains(ch))
    })
}

/// Hides `text[at..end]` whole, outer blanks dropped.
pub(super) fn whole(text: &str, at: usize, end: usize, spans: &mut Vec<(usize, usize)>) {
    let line = &text[at..end];
    let start = at + line.len() - line.trim_start().len();
    if start < at + line.trim_end().len() {
        spans.push((start, at + line.trim_end().len()));
    }
}
