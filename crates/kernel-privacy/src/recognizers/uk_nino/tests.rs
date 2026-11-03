//! Unit tests for the UK National Insurance number recogniser, split by topic.

use super::UkNinoRecognizer;
use crate::recognizer::Recognizer;

mod basic;
mod chain;
mod loose;

fn hits(text: &str) -> Vec<&str> {
    UkNinoRecognizer::new()
        .analyze(text)
        .into_iter()
        .map(|span| &text[span.start..span.end])
        .collect()
}
