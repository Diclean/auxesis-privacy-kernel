//! Unit tests for the label-value recogniser, split by topic.

use super::LabelValueRecognizer;
use crate::recognizer::Recognizer;

mod basic;
mod blood;
mod ids;
mod lexicon;
mod links;

fn masked(text: &str) -> Vec<&str> {
    let spans = LabelValueRecognizer::new().analyze(text);
    spans
        .iter()
        .map(|span| &text[span.start..span.end])
        .collect()
}
