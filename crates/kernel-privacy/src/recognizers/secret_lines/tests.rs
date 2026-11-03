//! Unit tests for the secret-line scans, split by topic.

use super::header::folded;
use super::lines_scan;

mod folding;
mod forms;
mod linear;

fn hidden(text: &str) -> Vec<&str> {
    lines_scan(text).iter().map(|&(s, e)| &text[s..e]).collect()
}
