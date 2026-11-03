//! Merging token maps, and comparing two surfaces the way a token was minted.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use unicode_normalization::UnicodeNormalization;

use crate::anonymize::{casefold, kind_of_token, normalize_value, TokenMap};
use crate::span::EntityKind;

use super::VaultError;

/// Whether two surfaces kept under one token are the same value: equal once
/// folded the way the token was minted. A token with no known kind matches on
/// folded text.
fn same_value(token: &str, first: &str, second: &str) -> bool {
    match kind_of_token(token) {
        Some(kind) => normalize_value(kind, first) == normalize_value(kind, second),
        None => fold_text(first) == fold_text(second),
    }
}

/// Whether `stored`, kept under `token`, is the value an erasure names. Both
/// sides are folded under the token's kind, the same fold the token was minted
/// with, so `06 12 34 56 78` and `0612345678` match, and an e-mail matches in
/// any case. A textual kind (a name, a place) keys its token on the exact
/// spelling, but an erasure compares it with [`fold_text`], so `Camille
/// Exemple` and `CAMILLE EXEMPLE` are one person. A token with no known kind
/// compares folded text.
pub(super) fn erases(token: &str, stored: &str, value: &str) -> bool {
    match kind_of_token(token) {
        Some(kind) if is_textual(kind) => fold_text(stored) == fold_text(value),
        Some(kind) => normalize_value(kind, stored) == normalize_value(kind, value),
        None => fold_text(stored) == fold_text(value),
    }
}

/// Whether `kind` is a textual kind: neither an identifier nor an e-mail.
fn is_textual(kind: EntityKind) -> bool {
    !(kind.is_identifier() || kind == EntityKind::Email)
}

/// NFKC, trim, then full case folding: the comparison for text with no known
/// kind.
fn fold_text(text: &str) -> String {
    let folded: String = text.nfkc().collect();
    casefold(folded.trim())
}

/// Adds the entries and occurrences of `from` to `into`. A token already mapped
/// to the same value keeps its entry. A token mapped to a different value fails
/// the whole merge, and `into` is left untouched.
pub(super) fn merge(into: &mut TokenMap, from: &TokenMap) -> Result<(), VaultError> {
    let mut known: HashMap<&str, &str> = into
        .iter()
        .map(|(token, original)| (token.as_str(), original.as_str()))
        .collect();
    let mut fresh: Vec<(String, String)> = Vec::new();
    for (token, original) in from.iter() {
        match known.entry(token.as_str()) {
            Entry::Occupied(first) => {
                if !same_value(token, first.get(), original) {
                    return Err(VaultError::TokenConflict);
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(original.as_str());
                fresh.push((token.clone(), original.clone()));
            }
        }
    }
    for (token, original) in from.occurrences() {
        match known.get(token.as_str()) {
            Some(first) if same_value(token, first, original) => {}
            Some(_) => return Err(VaultError::TokenConflict),
            None => return Err(VaultError::Corrupt("occurrence without a mapping")),
        }
    }
    for (token, original) in fresh {
        into.push_entry(token, original);
    }
    for (token, original) in from.occurrences() {
        into.push_occurrence(token.clone(), original.clone());
    }
    Ok(())
}
