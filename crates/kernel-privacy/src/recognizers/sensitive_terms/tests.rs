//! Tests for the sensitive-terms recogniser.

mod folding;
mod han;
mod lexicon;

use crate::recognizer::Recognizer;

use super::SensitiveTermsRecognizer;

fn hits(text: &str) -> Vec<String> {
    SensitiveTermsRecognizer::new()
        .analyze(text)
        .into_iter()
        .map(|span| text[span.start..span.end].to_string())
        .collect()
}
