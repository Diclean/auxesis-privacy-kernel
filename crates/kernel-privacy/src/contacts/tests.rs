//! Shared fixtures for the contact index tests, split by topic.

mod identifiers;
mod limits;
mod matching;
mod merging;
mod windows;

use zeroize::Zeroizing;

use crate::recognizer::Recognizer;
use crate::span::EntityKind;

use super::{ContactIndex, PersonDraft, SeedLimits};

/// Strings as a draft holds them: zeroized on drop.
fn zs(values: &[&str]) -> Vec<Zeroizing<String>> {
    values
        .iter()
        .map(|value| Zeroizing::new(value.to_string()))
        .collect()
}

fn draft(given: &str, family: &str, emails: &[&str]) -> PersonDraft {
    PersonDraft {
        given: zs(&[given]),
        family: zs(&[family]),
        emails: zs(emails),
        ..PersonDraft::default()
    }
}

/// An index that masks first names too (the option is off by default).
fn first_names_masked() -> ContactIndex {
    ContactIndex::with_options(SeedLimits::DEFAULT, true)
}

fn masked_kinds(index: &ContactIndex, text: &str) -> Vec<(EntityKind, String)> {
    index
        .recognizer()
        .expect("build")
        .analyze(text)
        .into_iter()
        .map(|span| (span.kind, text[span.start..span.end].to_string()))
        .collect()
}

fn masked_by_contacts(index: &ContactIndex, text: &str) -> Vec<(String, u32)> {
    let recognizer = index.recognizer().expect("build");
    recognizer
        .analyze(text)
        .into_iter()
        .filter(|span| span.kind == EntityKind::Person)
        .map(|span| {
            (
                text[span.start..span.end].to_string(),
                span.person_id.unwrap_or(u32::MAX),
            )
        })
        .collect()
}
