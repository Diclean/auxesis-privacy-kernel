//! Unit tests for the prose scan, split by topic.

use super::prose_scan;

mod cookies;
mod links;

fn hidden(text: &str) -> Vec<&str> {
    prose_scan(text)
        .into_iter()
        .map(|(s, e)| &text[s..e])
        .collect()
}
