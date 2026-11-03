//! Corpus loading: the JSONL case shape and the file/directory reader.

use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::EntityKind;
use serde::Deserialize;

/// The owner's private-mode languages (2026-10-10). Tier C is scored on these
/// only; a case in any other language is printed on an unscored row.
pub(crate) const IN_SCOPE_LANGS: [&str; 6] = ["fr", "en", "af", "hu", "sl", "zh"];

/// Whether a case's language is one the owner declared.
pub(crate) fn in_scope(lang: &str) -> bool {
    IN_SCOPE_LANGS.contains(&lang)
}

#[derive(Deserialize)]
pub(crate) struct Case {
    pub(crate) id: String,
    pub(crate) lang: String,
    pub(crate) text: String,
    pub(crate) spans: Vec<Gold>,
}

#[derive(Deserialize)]
pub(crate) struct Gold {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

/// Convert a Unicode code-point index to a UTF-8 byte offset.
pub(crate) fn cp_to_byte(text: &str, cp: usize) -> usize {
    text.char_indices()
        .nth(cp)
        .map(|(byte, _)| byte)
        .unwrap_or(text.len())
}

/// Gold spans of one case, with code-point offsets converted to bytes.
pub(crate) fn gold_spans(case: &Case) -> Vec<GoldSpan> {
    case.spans
        .iter()
        .filter_map(|labelled| {
            let kind = EntityKind::parse(&labelled.kind)?;
            Some(GoldSpan::new(
                kind,
                cp_to_byte(&case.text, labelled.start),
                cp_to_byte(&case.text, labelled.end),
            ))
        })
        .collect()
}

pub(crate) fn read_cases(paths: &[PathBuf]) -> Result<Vec<Case>, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    for path in paths {
        if path.is_dir() {
            let entries =
                fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))?;
            let mut found: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|entry| entry.extension().is_some_and(|ext| ext == "jsonl"))
                .collect();
            found.sort();
            files.extend(found);
        } else {
            files.push(path.clone());
        }
    }
    let mut cases = Vec::new();
    for file in files {
        let handle = File::open(&file).map_err(|error| format!("{}: {error}", file.display()))?;
        for (line_number, line) in BufReader::new(handle).lines().enumerate() {
            let line = line.map_err(|error| format!("{}: {error}", file.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            let case: Case = serde_json::from_str(&line).map_err(|error| {
                format!(
                    "{}:{}: malformed JSON: {error}",
                    file.display(),
                    line_number + 1
                )
            })?;
            cases.push(case);
        }
    }
    Ok(cases)
}
