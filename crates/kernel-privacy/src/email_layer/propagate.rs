//! Propagation of seeded names across the whole decoded text.

use std::collections::{HashMap, HashSet};

use crate::decode::DecodedText;
use crate::span::{EntityKind, Span};

use super::lines::{is_word_separator, word_tokens, WordToken};
use super::mail_words::STRUCTURAL_WORDS;
use super::nameset::NameSet;
use super::signals::is_honorific;
use super::{EmailLayer, PROPAGATION_SCORE};

impl EmailLayer {
    /// Mask every other occurrence of a seeded name token.
    ///
    /// Three rules, in the order the maintainer fixed them:
    ///
    /// * (c) a token from a strong seed that is not structural always propagates
    ///   (over stop words and public terms); a bare given name alone propagates
    ///   only when [`EmailLayer::with_first_names`] is on;
    /// * (a) a structural token that is part of a strong seed's full sequence is
    ///   masked with it, in any order of given and family name, with an initial
    ///   (`J. De`, `De J.`) or an honorific (`M. De`);
    /// * (b) a structural token from a strong seed is masked alone only in the
    ///   exact spelling the seed used, off a line or sentence start and not
    ///   followed by a lower-case word.
    pub(super) fn propagate(
        &self,
        decoded: &DecodedText,
        names: &NameSet<'_>,
        emails: &[Span],
    ) -> Vec<Span> {
        if names.is_empty() {
            return Vec::new();
        }
        let text = decoded.text();
        let tokens = word_tokens(text);
        let mut masked = vec![false; tokens.len()];

        for (index, token) in tokens.iter().enumerate() {
            if names.is_always(&token.folded)
                || (self.mask_first_names && names.is_given(&token.folded))
            {
                masked[index] = true;
            }
        }
        mark_sequences(&tokens, text, &names.sequences, &mut masked);
        mark_honorifics(&tokens, text, names, &mut masked);
        for (index, slot) in masked.iter_mut().enumerate() {
            *slot |= names.is_lone_structural(text, &tokens, index);
        }
        // A token inside an e-mail address is masked as part of that address.
        // It must not join a name phrase that precedes it: the display name and
        // the address stay two regions (and two tokens) even when the address
        // local part repeats the name.
        // Sorted by start, with the running maximum end: one search per token.
        let mut emails: Vec<(usize, usize)> = emails.iter().map(|e| (e.start, e.end)).collect();
        emails.sort_unstable();
        let ends: Vec<usize> = emails
            .iter()
            .scan(0, |reach, &(_, end)| {
                *reach = end.max(*reach);
                Some(*reach)
            })
            .collect();
        for (index, token) in tokens.iter().enumerate() {
            let before = emails.partition_point(|&(start, _)| start < token.end);
            if before > 0 && ends[before - 1] > token.start {
                masked[index] = false;
            }
        }

        let mut matches: Vec<(usize, usize)> = Vec::new();
        for (index, token) in tokens.iter().enumerate() {
            if !masked[index] {
                continue;
            }
            if let Some(last) = matches.last_mut() {
                let gap = &text[last.1..token.start];
                if gap.len() <= 4 && gap.chars().all(is_word_separator) {
                    last.1 = token.end;
                    continue;
                }
            }
            matches.push((token.start, token.end));
        }
        let mut spans = Vec::new();
        for (start, mut end) in matches {
            // A masked initial keeps its dot, so `De J.` masks as written.
            if end < text.len()
                && text[end..].starts_with('.')
                && text[..end]
                    .chars()
                    .rev()
                    .take_while(|ch| ch.is_alphanumeric())
                    .count()
                    == 1
            {
                end += 1;
            }
            if let Some((orig_start, orig_end)) = decoded.source_bounds(start, end) {
                spans.push(Span::new(
                    EntityKind::Person,
                    orig_start,
                    orig_end,
                    PROPAGATION_SCORE,
                    "email_layer_name",
                ));
            }
        }
        spans
    }
}

/// Mask an honorific and the seeded name right after it (`M. De`, `Dr Jean`).
fn mark_honorifics(tokens: &[WordToken], text: &str, names: &NameSet<'_>, masked: &mut [bool]) {
    for (index, pair) in tokens.windows(2).enumerate() {
        if !is_honorific(&pair[0].folded) {
            continue;
        }
        let next = &pair[1];
        let named = names.is_always(&next.folded)
            || names.is_given(&next.folded)
            || (names.structural.contains_key(&next.folded)
                && text[next.start..next.end]
                    .chars()
                    .next()
                    .is_some_and(char::is_uppercase));
        if named {
            masked[index] = true;
            masked[index + 1] = true;
        }
    }
}

/// Mask every occurrence of each strong seed's token sequence, in any order.
///
/// A seed token that is structural is only masked in its capitalised surname
/// shape: a lower-case article `de`/`le` belongs to every French mail, and the
/// seed's own sequence (`Jean De`) must not turn it into a name. A
/// non-structural seed token also matches a one-letter initial (`J. De`).
///
/// One pass per length, not per seed (K-REGISTRY-PERF: a pass each was
/// quadratic over a long log). A window token longer than one letter matches
/// only an equal seed token, so a window is compared only with the sequences
/// holding its rarest such token; a window of initials, with the sequences of
/// the same first letters. No other sequence can match it.
pub(super) fn mark_sequences(
    tokens: &[WordToken],
    text: &str,
    seeds: &[Vec<String>],
    masked: &mut [bool],
) {
    let mut seen: HashSet<&[String]> = HashSet::new();
    let mut lengths: Vec<usize> = Vec::new();
    let mut by_token: HashMap<(usize, &str), Vec<&[String]>> = HashMap::new();
    let mut by_initials: HashMap<Vec<char>, Vec<&[String]>> = HashMap::new();
    for sequence in seeds {
        if sequence.is_empty() || !seen.insert(sequence) {
            continue;
        }
        let length = sequence.len();
        if !lengths.contains(&length) {
            lengths.push(length);
        }
        let mut words: Vec<&str> = sequence.iter().map(String::as_str).collect();
        words.sort_unstable();
        words.dedup();
        for word in words {
            by_token.entry((length, word)).or_default().push(sequence);
        }
        let initials = first_letters(sequence.iter().map(String::as_str));
        by_initials.entry(initials).or_default().push(sequence);
    }
    for length in lengths {
        for (start, window) in tokens.windows(length).enumerate() {
            let rarest = window
                .iter()
                .filter(|token| token.folded.chars().count() != 1)
                .map(|token| by_token.get(&(length, token.folded.as_str())))
                .min_by_key(|found| found.map_or(0, Vec::len));
            let candidates = match rarest {
                Some(found) => found,
                None => by_initials.get(&first_letters(window.iter().map(|t| t.folded.as_str()))),
            };
            let Some(candidates) = candidates else {
                continue;
            };
            if candidates
                .iter()
                .any(|sequence| window_matches_any_order(sequence, window, text))
            {
                for slot in masked.iter_mut().skip(start).take(length) {
                    *slot = true;
                }
            }
        }
    }
}

/// The first letter of each word, sorted: the key two words lists must share
/// for one to match the other through initials.
fn first_letters<'w>(words: impl Iterator<Item = &'w str>) -> Vec<char> {
    let mut letters: Vec<char> = words.filter_map(|word| word.chars().next()).collect();
    letters.sort_unstable();
    letters
}

/// Whether `window` is a permutation of `sequence`, each pair allowed to match
/// with an initial.
pub(super) fn window_matches_any_order(
    sequence: &[String],
    window: &[WordToken],
    text: &str,
) -> bool {
    if sequence.len() != window.len() {
        return false;
    }
    fn assign(
        sequence: &[String],
        window: &[WordToken],
        text: &str,
        index: usize,
        used: &mut [bool],
    ) -> bool {
        if index == sequence.len() {
            return true;
        }
        for slot in 0..window.len() {
            if used[slot] || !token_matches(&sequence[index], &window[slot], text) {
                continue;
            }
            used[slot] = true;
            if assign(sequence, window, text, index + 1, used) {
                return true;
            }
            used[slot] = false;
        }
        false
    }
    let mut used = vec![false; window.len()];
    assign(sequence, window, text, 0, &mut used)
}

/// Whether a window token matches one seed token.
fn token_matches(seed: &str, token: &WordToken, text: &str) -> bool {
    if STRUCTURAL_WORDS.contains(seed) {
        return token.folded == seed
            && text[token.start..token.end]
                .chars()
                .next()
                .is_some_and(char::is_uppercase);
    }
    token.folded == seed || initial_matches(seed, &token.folded)
}

/// Whether `folded` is a one-letter initial of the seed word.
fn initial_matches(seed: &str, folded: &str) -> bool {
    let mut seed_chars = seed.chars();
    let mut folded_chars = folded.chars();
    match (seed_chars.next(), folded_chars.next(), folded_chars.next()) {
        (Some(first), Some(only), None) => only == first,
        _ => false,
    }
}
