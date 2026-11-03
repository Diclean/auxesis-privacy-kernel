//! Passport cue detection and the cue-less spaced-shape policy.

use super::checks::check_score;

/// Characters inspected before and after a candidate for a passport cue.
pub(super) const CUE_WINDOW: usize = 64;
/// Cue words that widen the shape (P1). `P<` is the MRZ document-code prefix;
/// matching is case-insensitive, so `p<` covers it.
const CUES: &[&str] = &[
    "passeport",
    "passport",
    "paspoort",
    "útlevél",
    "паспорт",
    "جواز",
    "mrz",
    "p<",
];

/// Letter prefixes that are a cue for another recogniser, so the specific rule
/// decides both the label and the span: a spaced `TAJ 123456788` stays the
/// Hungarian TAJ hit and `ISO 123456` is an international standard.
const NON_PASSPORT_PREFIXES: &[&str] = &["iso", "taj"];

/// Common business-reference prefixes that stay clear in the *cue-less spaced*
/// form, so an order/invoice/article reference (`REF 1234567`) is not masked as
/// a passport. Deliberately short and only consulted for the space-separated
/// shape, after a whole-word prefix; the hyphen/dot forms are unambiguous
/// attachment and still mask. `N°` is listed for completeness even though the
/// `°` means the separated regex never yields it as a prefix.
const BUSINESS_PREFIXES: &[&str] = &["ref", "inv", "fa", "cmd", "po", "no", "n°", "nr", "art"];

/// Whether a space-separated strict shape is a passport without a cue.
///
/// The cue-less spaced form is masked on shape alone for *every* 1–3 letter
/// prefix and 7–9 digits (P2: `E 12345678` and `AB 1234567` used to leak), so a
/// bare OCR line or a CSV cell no longer depends on a three-letter prefix.
/// Two short exceptions stay clear because the prefix is a word with another
/// meaning: `ISO` heads an international-standard number, and the
/// [`BUSINESS_PREFIXES`] head an order or article reference. A prefix that cues
/// another rule (`TAJ`) is left to that rule. A de-spaced value whose ICAO
/// 7-3-1 check digit validates is still the strongest signal and is masked.
pub(super) fn spaced_without_cue_is_passport(value: &str) -> bool {
    let Some((prefix, digits)) = value.split_once(' ') else {
        return false;
    };
    if NON_PASSPORT_PREFIXES
        .iter()
        .chain(BUSINESS_PREFIXES.iter())
        .any(|known| prefix.eq_ignore_ascii_case(known))
    {
        return false;
    }
    // (a) A valid 7-3-1 check digit is the strongest passport signal.
    let de_spaced: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    if check_score(&de_spaced).is_some() {
        return true;
    }
    // (b) The cue-less shape `[A-Z]{1,3} [0-9]{7,9}` masks for every prefix
    // length; a 6-digit tail is too weak to stand alone.
    (1..=3).contains(&prefix.len()) && (7..=9).contains(&digits.len())
}

/// Whether a passport cue appears within [`CUE_WINDOW`] characters before *or*
/// after the `start..end` value.
pub(super) fn near_cue(text: &str, start: usize, end: usize) -> bool {
    let begin = text[..start]
        .char_indices()
        .rev()
        .nth(CUE_WINDOW)
        .map(|(index, _)| index)
        .unwrap_or(0);
    let finish = text[end..]
        .char_indices()
        .nth(CUE_WINDOW)
        .map(|(index, _)| end + index)
        .unwrap_or(text.len());
    let window = text[begin..finish].to_lowercase();
    CUES.iter().any(|cue| window.contains(cue))
}
