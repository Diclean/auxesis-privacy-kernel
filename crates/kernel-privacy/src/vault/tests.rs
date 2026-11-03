//! Shared fixtures for the vault tests; the groups are child modules.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::TempDir;

use crate::anonymize::{Anonymizer, UnknownPolicy};
use crate::span::{EntityKind, Span};

use super::paths::{hex, slot_for};
use super::*;

const KEY: [u8; 32] = [7; 32];
const EMAIL: &str = "jean.dupont@example.test";
const PHONE: &str = "06 12 34 56 78";
const TEXT: &str = "Écrivez à jean.dupont@example.test ou au 06 12 34 56 78.";
const OTHER: &str = "Écrivez à marie@example.test.";

fn span_of(text: &str, needle: &str, kind: EntityKind) -> Span {
    let start = text.find(needle).expect("needle is in the text");
    Span {
        kind,
        start,
        end: start + needle.len(),
        score: 1.0,
        recognizer: "test",
        person_id: None,
    }
}

/// Masks `text`, marking each `(needle, kind)` pair, with the given key.
fn mask(key: [u8; 32], text: &str, needles: &[(&str, EntityKind)]) -> (String, TokenMap) {
    let spans: Vec<Span> = needles
        .iter()
        .map(|(needle, kind)| span_of(text, needle, *kind))
        .collect();
    Anonymizer::new(key).anonymize(text, &spans)
}

fn mask_text(key: [u8; 32]) -> (String, TokenMap) {
    mask(
        key,
        TEXT,
        &[(EMAIL, EntityKind::Email), (PHONE, EntityKind::Phone)],
    )
}

/// A map with one token, shown once as `original`.
fn single(token: &str, original: &str) -> TokenMap {
    let mut map = TokenMap::default();
    map.push_entry(token.to_owned(), original.to_owned());
    map.push_occurrence(token.to_owned(), original.to_owned());
    map
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Arms `point` on this thread: the next operation that reaches it fails.
fn arm_crash(point: CrashPoint) {
    CRASH_AT.with(|armed| armed.set(Some(point)));
}

/// The generation of the session's record on disk, and of its manifest entry.
fn generations(vault: &Vault, session_id: &str) -> (Option<u64>, u64) {
    let slot = slot_for(session_id);
    let record = vault
        .open_record(&slot)
        .unwrap()
        .map(|record| record.generation);
    (record, vault.load_manifest().unwrap().generation(&slot))
}

/// Sets the session's manifest generation, as a restored manifest would.
fn set_manifest(vault: &Vault, session_id: &str, generation: u64) {
    let mut manifest = vault.load_manifest().unwrap();
    vault
        .set_generation(&mut manifest, &slot_for(session_id), generation)
        .unwrap();
}

/// Writes `map` as the session's record at `generation`, through the vault's
/// own write path: the manifest is set one below, then the record is written.
fn record_at(vault: &Vault, session_id: &str, map: &TokenMap, generation: u64) {
    set_manifest(vault, session_id, generation - 1);
    vault.record(session_id, map).unwrap();
}

/// One call to each public operation on `session-a`, with its result.
fn run_each(vault: &Vault, map: &TokenMap) -> Vec<(&'static str, Result<(), VaultError>)> {
    vec![
        ("lookup", vault.lookup("session-a").map(|_| ())),
        ("record", vault.record("session-a", map)),
        (
            "forget_session",
            vault.forget_session("session-a").map(|_| ()),
        ),
        ("forget_value", vault.forget_value(EMAIL).map(|_| ())),
    ]
}

mod basics;
mod erasure;
mod limits;
mod recovery;
