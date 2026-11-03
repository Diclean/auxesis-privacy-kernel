//! Display-name and rule-token extraction from a header, greeting or line.

use crate::name_lexicon;
use crate::public_terms::fold;

use super::cues::{
    CLOSINGS, GREETINGS, QUESTION_OPENERS, REPLY_VERBS, SENDER_KEYS, SPEECH_VERBS, SUBJECT_KEYS,
    TITLES,
};
use super::function_words::FUNCTION_WORDS;
use super::lines::{lower_mapped, original_at, strip_quote_prefix, word_tokens, WordToken};
use super::mail_words::{STRUCTURAL_PARTICLES, STRUCTURAL_WORDS};
use super::nameset::NameSet;
use super::signals::{joined_by_separator, ps_marker_end};

/// Whether `line` starts with a greeting; returns the byte length of it.
pub(super) fn starts_with_greeting(line: &str) -> Option<usize> {
    // A lowered length is no `line` length when lower-casing changes a
    // character's (`Hİ` -> `hi̇`): map it back, or there is no greeting.
    let (lowered, map) = lower_mapped(line);
    for greeting in GREETINGS {
        if let Some(after) = lowered.strip_prefix(greeting) {
            if after.chars().next().is_none_or(|ch| !ch.is_alphanumeric()) {
                if let Some(end) = original_at(&map, greeting.len()) {
                    return Some(end);
                }
            }
        }
    }
    None
}

/// Whether `line` starts with a closing word.
pub(super) fn is_closing(line: &str) -> bool {
    let lowered = line.to_lowercase();
    CLOSINGS.iter().any(|closing| {
        lowered
            .strip_prefix(closing)
            .is_some_and(|after| after.chars().next().is_none_or(|ch| !ch.is_alphanumeric()))
    })
}

/// The author part of a `P.S.` / `PS` / `NB` line, as a slice of `line` that runs
/// to its end, or `None`.
pub(super) fn ps_rest(line: &str) -> Option<&str> {
    let at = ps_marker_end(line)?;
    let rest = line[at..].trim_start_matches([':', '.', ' ', '\t']);
    (!rest.is_empty()).then_some(rest)
}

/// Whether the picked tokens open with a known given name, or with two
/// capitalized words: a name, not a record or a sentence.
pub(super) fn opens_with_a_name(head: &str, picked: &[WordToken]) -> bool {
    picked
        .first()
        .is_some_and(|token| name_lexicon::is_given_name(&token.folded))
        || (picked.len() >= 2
            && picked.iter().take(2).all(|token| {
                head[token.start..token.end]
                    .chars()
                    .next()
                    .is_some_and(char::is_uppercase)
            }))
}

/// Whether `head` holds a word that is neither a picked name token, a title,
/// a one-letter initial nor a surname particle.
pub(super) fn has_words_beyond_the_name(head: &str, picked: &[WordToken]) -> bool {
    word_tokens(head).iter().any(|token| {
        let folded = token.folded.as_str();
        !picked.iter().any(|name| name.start == token.start)
            && !TITLES.iter().any(|title| fold(title) == folded)
            && folded.chars().count() > 1
            && !STRUCTURAL_PARTICLES.contains(&folded)
    })
}

/// Whether a line head is written in a Latin script (it holds an ASCII letter).
pub(super) fn is_latin_head(head: &str) -> bool {
    head.chars().any(|ch| ch.is_ascii_alphabetic())
}

/// Whether a line head opens like a question or a request (see
/// [`QUESTION_OPENERS`]) or holds a function word after a capitalized opener.
pub(super) fn is_question_opening(head: &str) -> bool {
    let Some(first) = word_tokens(head).into_iter().next() else {
        return false;
    };
    if !is_latin_head(head) {
        return false;
    }
    QUESTION_OPENERS.contains(&first.folded.as_str())
        || (FUNCTION_WORDS.contains(&first.folded.as_str())
            && !STRUCTURAL_PARTICLES.contains(&first.folded.as_str())
            && word_tokens(head).len() > 1)
}

/// Collect up to `max` name tokens from the front of `value`.
///
/// A rule that names a person (a greeting, a sign-off, a header, a line-initial
/// comma, a speech verb) is strong evidence, so a capitalized stop word or public
/// term is still taken as a name. A lower-case function word ends the run: it
/// would seed a modal verb or an article from every mail.
pub(super) fn pick_rule_tokens(value: &str, names: &NameSet<'_>, max: usize) -> Vec<WordToken> {
    let mut picked = Vec::new();
    // A surname particle (`van`, `al`, `Mac`) is not a name on its own, but it
    // joins the name that follows; hold it until a name-shaped token confirms
    // the phrase (`van der Berg`).
    let mut pending: Vec<WordToken> = Vec::new();
    for token in word_tokens(value) {
        if picked.len() >= max {
            break;
        }
        let folded = token.folded.as_str();
        if TITLES.iter().any(|title| fold(title) == folded) || !NameSet::is_name_like(folded) {
            // A title or a one-letter initial never seeds on its own, but it
            // does not end the name either ("Dr. H. Nel").
            continue;
        }
        let raw = &value[token.start..token.end];
        if names.is_rule_name(&token, raw) {
            let room = max.saturating_sub(picked.len() + 1);
            for (index, particle) in pending.drain(..).enumerate() {
                if index >= room {
                    break;
                }
                picked.push(particle);
            }
            pending.clear();
            if picked.len() >= max {
                break;
            }
            picked.push(token);
        } else if STRUCTURAL_PARTICLES.contains(&folded) {
            pending.push(token);
        } else {
            break;
        }
    }
    picked
}

/// Whether `line` (already trimmed) is a subject header.
pub(super) fn subject_rest(line: &str) -> Option<&str> {
    let lowered = line.to_lowercase();
    let is_subject = SUBJECT_KEYS.iter().any(|key| {
        lowered
            .strip_prefix(*key)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    });
    if !is_subject {
        return None;
    }
    let colon = line.find(':')?;
    Some(&line[colon + 1..])
}

/// The display name of a sender header or a reply line: its byte range inside
/// `line` plus the tokens that seed propagation.
///
/// A structural token that lies inside the picked run or directly after it is
/// the surname the seed was cut at ("Jean De", "Jean de la Cruz"), so it seeds
/// too. A structural token before the first picked token is an article or a
/// header label ("De : Le Monde" names "Monde"), so it does not.
pub(super) fn display_name(
    line: &str,
    names: &NameSet<'_>,
) -> Option<(usize, usize, Vec<WordToken>)> {
    let offset = strip_quote_prefix(line);
    let body = &line[offset..];
    let lowered = body.to_lowercase();
    let is_sender = SENDER_KEYS.iter().any(|key| {
        lowered
            .strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    });
    let is_reply = REPLY_VERBS
        .iter()
        .copied()
        .chain(SPEECH_VERBS.iter().map(|(verb, _)| *verb))
        .any(|verb| lowered.contains(verb));
    if !is_sender && !is_reply {
        return None;
    }
    let mut picked: Vec<WordToken> = Vec::new();
    // The region the picked run lives in, and the shift that maps one of its
    // tokens back to a `body` offset.
    let (region, shift): (&str, usize);
    if let Some(angle) = body.find('<') {
        region = &body[..angle];
        shift = 0;
        for token in word_tokens(region).into_iter().rev() {
            if STRUCTURAL_WORDS.contains(&token.folded) {
                // A header label or an article is not part of the name
                // ("De : Le Monde" names "Monde"); skip it and keep walking.
                continue;
            }
            if picked.len() >= 4 || !names.is_rule_name(&token, body) {
                break;
            }
            picked.push(token);
        }
    } else if is_sender {
        let start = body.find(':').map(|colon| colon + 1).unwrap_or(0);
        // A sender without an angle address can still carry a bracketed
        // `[mailto:…]`: stop the display name before it, so the person span
        // never reaches into the address.
        let value = &body[start..];
        let cut = value
            .char_indices()
            .find(|(_, ch)| matches!(ch, '[' | '<' | '(' | '|'))
            .map(|(index, _)| index)
            .unwrap_or(value.len());
        region = &value[..cut];
        shift = start;
        for mut token in word_tokens(region) {
            if STRUCTURAL_WORDS.contains(&token.folded) {
                continue;
            }
            if picked.len() >= 4 || !names.is_rule_name(&token, value) {
                break;
            }
            token.start += start;
            token.end += start;
            picked.push(token);
        }
    } else {
        return None;
    }
    if picked.is_empty() {
        return None;
    }
    let mut begin = picked.iter().map(|token| token.start).min()?;
    let mut end = picked.iter().map(|token| token.end).max()?;
    // Keep the structural tokens that belong to the run: the interior ones, plus
    // the trailing run a surname may form right before the address.
    let mut seeds: Vec<WordToken> = Vec::new();
    for token in word_tokens(region) {
        if !STRUCTURAL_WORDS.contains(&token.folded) {
            continue;
        }
        let start = token.start + shift;
        let stop = token.end + shift;
        if start < begin || !joined_by_separator(body, end.min(start), start) {
            continue;
        }
        end = end.max(stop);
        seeds.push(WordToken {
            start,
            end: stop,
            folded: token.folded,
        });
    }
    // A leading surname particle joins the name it precedes (`van der Berg`,
    // `Mac Donald`). Walk backwards so `van` is reached after `der` widened the
    // run. Other leading structural tokens are labels, not names.
    for token in word_tokens(region).into_iter().rev() {
        if !STRUCTURAL_WORDS.contains(&token.folded)
            || !STRUCTURAL_PARTICLES.contains(&token.folded.as_str())
        {
            continue;
        }
        let start = token.start + shift;
        let stop = token.end + shift;
        if stop > begin || !joined_by_separator(body, stop, begin) {
            continue;
        }
        begin = start;
        seeds.push(WordToken {
            start,
            end: stop,
            folded: token.folded,
        });
    }
    let mut tokens = picked;
    tokens.extend(seeds);
    // Text order, so the first token of a phrase is the given name even when a
    // leading particle (`van der Berg`) was collected after the surname.
    tokens.sort_by_key(|token| token.start);
    for token in &mut tokens {
        token.start += offset;
        token.end += offset;
    }
    Some((offset + begin, offset + end, tokens))
}
