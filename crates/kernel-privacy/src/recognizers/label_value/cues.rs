//! Health cues and the contexts that qualify a label or value.

use crate::recognizer::Recognizer;
use crate::recognizers::mrz::PassportMrzRecognizer;

use super::text::fold;

/// Words that make a `MEMBER` label a health one when one stands within
/// [`CUE_WINDOW`] bytes of it (folded: no accents, lower case).
const HEALTH_CUES: &str = "health healthcare medical patient patients clinic hospital medicare \
    medicaid dental pharmacy prescription nhs sante mutuelle hopital clinique medecin";
/// Words that make a `MEMBER` label a club's or a shop's when nearer to it than
/// any health word (`health club member ID`, `gym member ID`).
const NON_HEALTH_CUES: &str = "gym fitness loyalty rewards points club";
/// How far around a `MEMBER` label and its value a cue is looked for.
const CUE_WINDOW: usize = 120;

/// Whether the passport rule already masks `start..end` when it reads the label
/// from `from` on: its hit then keeps its own label and score (P3), never
/// displaced by this rule.
pub(super) fn passport_covers(text: &str, from: usize, start: usize, end: usize) -> bool {
    let spans = PassportMrzRecognizer::new().analyze(&text[from..end]);
    spans
        .iter()
        .any(|span| from + span.start <= start && end <= from + span.end)
}

/// Whether a health word stands within [`CUE_WINDOW`] bytes of the `MEMBER`
/// label at `from` and its value ending at `end`, nearer than any club or shop
/// word (`His health is fine; gym member ID …` is the gym's). The window is
/// bounded, so each label reads a constant span.
pub(super) fn health_cued(text: &str, from: usize, end: usize) -> bool {
    let start = text.floor_char_boundary(from.saturating_sub(CUE_WINDOW));
    let stop = text.ceil_char_boundary((end + CUE_WINDOW).min(text.len()));
    let (window, map) = fold(&text[start..stop]);
    let (mut health, mut other) = (usize::MAX, usize::MAX);
    let mut at = 0;
    for word in window.split(|c: char| !c.is_alphanumeric()) {
        let (first, last) = (start + map[at], start + map[at + word.len()]);
        at += word.len()
            + window[at + word.len()..]
                .chars()
                .next()
                .map_or(0, char::len_utf8);
        let distance = if last <= from {
            from - last
        } else {
            first.saturating_sub(end)
        };
        let is = |list: &str| !word.is_empty() && list.split(' ').any(|cue| cue == word);
        if is(HEALTH_CUES) {
            health = health.min(distance);
        } else if is(NON_HEALTH_CUES) {
            other = other.min(distance);
        }
    }
    health != usize::MAX && health <= other
}

/// Whether the label at `start` sits inside a path, a host or an identifier
/// (`portal/pin-login`, `certificate_license`): after `/`, `.`, `@`, `\`, or a
/// `_`/`-` glued to a letter or digit.
pub(super) fn inside_word(text: &str, start: usize) -> bool {
    let mut before = text[..start].chars().rev();
    match before.next() {
        Some('/' | '.' | '@' | '\\') => true,
        Some('_' | '-') => before.next().is_some_and(char::is_alphanumeric),
        _ => false,
    }
}
