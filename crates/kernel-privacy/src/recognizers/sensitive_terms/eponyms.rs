//! Eponym possessives used alone (`Hashimoto's`).

use super::disease::{health, name_like, HONORIFICS};
use super::lexicon::Hit;
use super::sentence::is_sentence_end;
use super::text::{joins, Word};

/// Folded eponyms whose possessive alone names the condition (`I have
/// Hashimoto's`). `Alzheimer`, `Parkinson` and `Crohn` are lexicon terms.
const EPONYM_POSSESSIVES: &[&str] = &[
    "hashimoto",
    "asperger",
    "tourette",
    "huntington",
    "raynaud",
    "addison",
    "cushing",
    "meniere",
    "hodgkin",
];

/// Folded words that may follow a possessive used alone: it owns no noun.
const AFTER_ALONE: &[&str] = &[
    "and", "or", "but", "so", "since", "for", "too", "as", "which", "that", "now", "again", "et",
    "ou", "mais", "donc", "depuis",
];

/// Folded words before a possessive that make it a place (`at Hashimoto's`).
const PLACE_BEFORE: &[&str] = &["at", "chez"];

/// Push an eponym's possessive used alone (`Our son has Asperger's, so…`):
/// the clause ends after it or a linking word follows. A noun after it (`Ms
/// Hashimoto's invoice`), an honorific or a place word before it keeps its text.
pub(super) fn push_eponym_possessives(text: &str, words: &[Word], out: &mut Vec<Hit>) {
    for (index, word) in words.iter().enumerate() {
        if !EPONYM_POSSESSIVES.contains(&word.folded.as_str()) || !name_like(text, word, false) {
            continue;
        }
        let Some(s) = words
            .get(index + 1)
            .filter(|s| s.folded == "s" && matches!(&text[word.end..s.start], "'" | "\u{2019}"))
        else {
            continue;
        };
        if let Some(before) = index.checked_sub(1).map(|at| &words[at]) {
            let gap = &text[before.end..word.start];
            let folded = before.folded.as_str();
            if (joins(text, before.end, word.start) || gap.starts_with('.'))
                && (HONORIFICS.contains(&folded) || PLACE_BEFORE.contains(&folded))
            {
                continue;
            }
        }
        // The first mark after it, from the text itself: a masked value's
        // stand-in in the residue view is no clause end, so a mask never makes
        // the possessive before it stand alone.
        let next = words.get(index + 2);
        let tail = next.map_or(&text[s.end..], |next| &text[s.end..next.start]);
        let alone = match tail.chars().find(|&ch| ch == '\n' || !ch.is_whitespace()) {
            Some(ch) => matches!(ch, ',' | ')') || is_sentence_end(ch),
            None => next.is_none_or(|next| AFTER_ALONE.contains(&next.folded.as_str())),
        };
        if alone {
            out.push(health(word.start, s.end, false, "en"));
        }
    }
}
