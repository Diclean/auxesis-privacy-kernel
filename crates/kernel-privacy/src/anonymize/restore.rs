//! Putting values back: [`Anonymizer::restore`] and the gate helper.

use std::collections::{HashMap, VecDeque};

use super::anonymizer::Anonymizer;
use super::placeholder::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN, UNKNOWN_REFERENCE};
use super::policy::{RestoreReport, UnknownPolicy};
use super::token_map::TokenMap;

impl Anonymizer {
    /// Replace every delimited placeholder in `text` with its original bytes.
    ///
    /// Parses the text left to right in a single pass. A doubled `⟦⟦` (a
    /// literal opener written by [`Anonymizer::anonymize`]) becomes one `⟦`;
    /// only the exact `⟦KIND_…⟧`
    /// delimiters are treated as placeholders, and only a token that is in
    /// `pairs` for this session is restored. An invented token, a token minted
    /// under another key, or any other text inside the delimiters is **not**
    /// restored: [`UnknownPolicy::Keep`] leaves it visible, while
    /// [`UnknownPolicy::Redact`] writes [`UNKNOWN_REFERENCE`]. Either way it is
    /// named in [`RestoreReport::unknown`] so the caller can hold the send.
    /// Undelimited token-like text is never touched.
    ///
    /// Per-occurrence surfaces are preserved: a token shared by two spellings
    /// restores each occurrence to its own exact surface form. This is an exact
    /// inverse of [`Anonymizer::anonymize`] for the map it returned.
    pub fn restore(text: &str, pairs: &TokenMap, unknown: UnknownPolicy) -> RestoreReport {
        let mut restored = String::with_capacity(text.len());
        let mut unresolved: Vec<String> = Vec::new();

        // Per-occurrence originals, consumed in masked order, so a shared token
        // restores each surface form byte for byte. `entries` is the fallback
        // when a known token appears more times than `anonymize` recorded.
        let mut queues: HashMap<&str, VecDeque<&str>> = HashMap::new();
        for (token, original) in &pairs.occurrences {
            if !token.is_empty() {
                queues
                    .entry(token.as_str())
                    .or_default()
                    .push_back(original.as_str());
            }
        }
        let entries: HashMap<&str, &str> = pairs
            .entries
            .iter()
            .map(|(token, original)| (token.as_str(), original.as_str()))
            .collect();

        let mut cursor = 0usize;
        let mut no_close = false;
        while cursor < text.len() {
            let ch = text[cursor..]
                .chars()
                .next()
                .expect("cursor is a char boundary");
            if ch == PLACEHOLDER_OPEN
                && text[cursor + PLACEHOLDER_OPEN.len_utf8()..].starts_with(PLACEHOLDER_OPEN)
            {
                // `⟦⟦` is the literal opener that `anonymize` wrote doubled.
                restored.push(PLACEHOLDER_OPEN);
                cursor += 2 * PLACEHOLDER_OPEN.len_utf8();
            } else if ch == PLACEHOLDER_OPEN {
                let inner_start = cursor + PLACEHOLDER_OPEN.len_utf8();
                let close = if no_close {
                    None
                } else {
                    text[inner_start..]
                        .find(PLACEHOLDER_CLOSE)
                        .map(|offset| inner_start + offset)
                };
                match close {
                    Some(inner_end) => {
                        let token = &text[inner_start..inner_end];
                        if token.is_empty() {
                            // `⟦⟧` is not one of our placeholders: keep it.
                            restored.push(PLACEHOLDER_OPEN);
                            restored.push(PLACEHOLDER_CLOSE);
                        } else if let Some(original) = queues
                            .get_mut(token)
                            .and_then(|queue| queue.pop_front())
                            .or_else(|| entries.get(token).copied())
                        {
                            restored.push_str(original);
                        } else {
                            unresolved.push(token.to_string());
                            match unknown {
                                UnknownPolicy::Keep => {
                                    restored.push(PLACEHOLDER_OPEN);
                                    restored.push_str(token);
                                    restored.push(PLACEHOLDER_CLOSE);
                                }
                                UnknownPolicy::Redact => restored.push_str(UNKNOWN_REFERENCE),
                            }
                        }
                        cursor = inner_end + PLACEHOLDER_CLOSE.len_utf8();
                    }
                    None => {
                        // No closing delimiter: the bracket is ordinary text.
                        // Once it is missing here, it is missing for every later
                        // open, so a run of `⟦` stays linear.
                        no_close = true;
                        restored.push(PLACEHOLDER_OPEN);
                        cursor = inner_start;
                    }
                }
            } else {
                restored.push(ch);
                cursor += ch.len_utf8();
            }
        }

        RestoreReport {
            text: restored,
            unknown: unresolved,
        }
    }
}

/// Put the real values back into an answer with a gate's minted pairs.
///
/// `minted` is the `(token, value)` list from
/// [`Gate::take_minted`](crate::safetext::Gate::take_minted). The parser is the
/// one [`Anonymizer::restore`] uses: a doubled `⟦⟦` becomes one literal `⟦`, a
/// known `⟦KIND_…⟧` becomes its value, and an unknown or malformed delimited
/// token follows `unknown` ([`UnknownPolicy::Keep`] leaves it visible,
/// [`UnknownPolicy::Redact`] writes [`UNKNOWN_REFERENCE`]). A marker with no
/// closing delimiter is ordinary text. Undelimited token-like text is never
/// touched.
///
/// This runs locally and returns text for the person who asked: never send the
/// result back to the model.
///
/// The gate reports one value per token, not every occurrence's spelling, so a
/// value the model wrote in a different spelling restores to the value the gate
/// reported. The pairs themselves are never printed.
#[must_use]
pub fn restore(answer: &str, minted: &[(String, String)], unknown: UnknownPolicy) -> String {
    // Reuse the one parser that already escapes openers and reads delimited
    // tokens left to right, so this helper cannot drift from `restore`'s
    // unknown-token and malformed-marker rules.
    let mut pairs = TokenMap::default();
    for (token, value) in minted {
        if !token.is_empty() {
            pairs.push_entry(token.clone(), value.clone());
        }
    }
    Anonymizer::restore(answer, &pairs, unknown).text
}
