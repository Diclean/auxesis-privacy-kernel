//! The fake corpus the harness scores: one case per JSONL line, plus the
//! synthetic long-thread documents the benchmark builds from the thread cases.

use std::fs;
use std::path::Path;

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::span::EntityKind;
use serde_json::Value;

const LANGS: [&str; 6] = ["fr", "en", "af", "hu", "ar", "ru"];
const SEP: &str = "\n\n---\n\n";

#[derive(Clone, Debug)]
pub(crate) struct Case {
    pub(crate) id: String,
    pub(crate) lang: String,
    pub(crate) kind: String,
    pub(crate) text: String,
    pub(crate) gold: Vec<GoldSpan>,
}

/// Parse one corpus file.
pub(crate) fn read_cases_file(path: &Path) -> Vec<Case> {
    let text =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let mut cases = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let value: Value = serde_json::from_str(line).expect("case JSON");
        let cases_text = value["text"].as_str().expect("text");
        // The corpus stores Unicode scalar indices (it is written by Python);
        // the recogniser emits byte offsets, so convert once here.
        let mut scalar_to_byte = Vec::with_capacity(cases_text.chars().count() + 1);
        for (byte, _) in cases_text.char_indices() {
            scalar_to_byte.push(byte);
        }
        scalar_to_byte.push(cases_text.len());
        let gold = value["spans"]
            .as_array()
            .expect("spans")
            .iter()
            .filter_map(|span| {
                let kind = EntityKind::parse(span["type"].as_str()?)?;
                let start = span["start"].as_u64()? as usize;
                let end = span["end"].as_u64()? as usize;
                Some(GoldSpan::new(
                    kind,
                    scalar_to_byte[start],
                    scalar_to_byte[end],
                ))
            })
            .collect();
        cases.push(Case {
            id: value["id"].as_str().expect("id").to_string(),
            lang: value["lang"].as_str().expect("lang").to_string(),
            kind: value["kind"].as_str().expect("kind").to_string(),
            text: cases_text.to_string(),
            gold,
        });
    }
    cases
}

pub(crate) fn read_cases(root: &Path) -> Vec<Case> {
    let mut cases = Vec::new();
    for lang in LANGS {
        cases.extend(read_cases_file(
            &root.join("cases").join(format!("{lang}.jsonl")),
        ));
    }
    cases
}

/// The Python benchmark's long-thread document: the four `thread` cases of one
/// language joined by a separator, gold spans shifted.
pub(crate) fn long_threads(cases: &[Case]) -> Vec<Case> {
    let mut docs = Vec::new();
    for lang in LANGS {
        let mut threads: Vec<&Case> = cases
            .iter()
            .filter(|case| case.lang == lang && case.kind == "thread")
            .collect();
        threads.sort_by(|left, right| left.id.cmp(&right.id));
        let mut text = String::new();
        let mut gold = Vec::new();
        let mut offset = 0usize;
        for (index, case) in threads.iter().enumerate() {
            if index > 0 {
                text.push_str(SEP);
                offset += SEP.len();
            }
            text.push_str(&case.text);
            gold.extend(
                case.gold
                    .iter()
                    .map(|span| GoldSpan::new(span.kind, span.start + offset, span.end + offset)),
            );
            offset += case.text.len();
        }
        docs.push(Case {
            id: format!("{lang}-longthread-synthetic"),
            lang: lang.to_string(),
            kind: "long_thread".to_string(),
            text,
            gold,
        });
    }
    docs
}
