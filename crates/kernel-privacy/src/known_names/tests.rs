//! Shared fixtures for the known-names tests, split by topic.

mod dictionary;
mod inflection;
mod matching;
mod scripts;

use crate::recognizer::Recognizer;
use crate::span::Span;

use super::NameDictionary;

fn spans(text: &str, names: &[&str]) -> Vec<Span> {
    NameDictionary::new(names)
        .expect("dictionary")
        .analyze(text)
}

fn found(text: &str, names: &[&str]) -> bool {
    !spans(text, names).is_empty()
}

/// Every probe in `(entry, probes)` must match with that entry.
fn assert_all(cases: &[(&str, &[&str])]) {
    for (entry, probes) in cases {
        let dictionary = NameDictionary::new([*entry]).expect("dictionary");
        for probe in *probes {
            assert!(
                !dictionary.analyze(probe).is_empty(),
                "{probe:?} with {entry:?} matched nothing"
            );
        }
    }
}
