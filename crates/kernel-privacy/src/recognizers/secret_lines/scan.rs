//! The four scans, run in order and merged into one span set.

use super::aws::glued_aws;
use super::cookies::cookies;
use super::labels::{labels, phrases};
use super::table::columns;

/// The secret spans of the four forms in `text`.
pub(crate) fn lines_scan(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    cookies(text, &mut spans);
    labels(text, &mut spans);
    let headers = columns(text, &mut spans);
    phrases(text, &headers, &mut spans);
    glued_aws(text, &mut spans);
    spans.sort_unstable();
    spans.dedup();
    spans
}

/// `text[start..end]` with quotes trimmed in pairs and outer blanks dropped.
pub(super) fn trimmed(text: &str, start: usize, end: usize) -> (usize, usize) {
    let cell = &text[start..end];
    let mut start = start + cell.len() - cell.trim_start().len();
    let mut end = start + text[start..end].trim_end().len();
    let cell = &text[start..end];
    if cell.len() >= 2 && (cell.starts_with('"') && cell.ends_with('"')) {
        start += 1;
        end -= 1;
    }
    (start, end)
}
