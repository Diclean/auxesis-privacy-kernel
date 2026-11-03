//! Unit tests for the passport/MRZ recogniser, split by topic.

use super::PassportMrzRecognizer;
use crate::recognizer::Recognizer;

mod cues;
mod recognizer;
mod rows;
mod shapes;

fn hits(text: &str) -> Vec<String> {
    PassportMrzRecognizer::new()
        .analyze(text)
        .into_iter()
        .map(|span| text[span.start..span.end].to_string())
        .collect()
}
