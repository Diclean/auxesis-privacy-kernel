//! A caller-supplied dictionary of known person names: the Tier H half of
//! Standard detection (D7). The owner application calls it: it passes the
//! names of its contacts to [`crate::safetext::Gate::for_grant_with_names`] or
//! [`crate::safetext::Gate::for_grant_with_dictionary`].
//!
//! The dictionary is local and exhaustive for the names it is given. For each
//! entry it compiles the surface forms a person is actually written under —
//! full name in either order, given or family name alone, initials, titles,
//! concatenations, possessives and elisions — and matches each one as a whole
//! word, case-, accent- and separator-insensitively. The caller seeds it from
//! the owner's contacts index (or any list the owner chose); it never leaves
//! the machine.
//!
//! Matching is script aware. A name written in a script without spaces (Han,
//! Hiragana, Katakana, Hangul, Thai, Lao, Khmer, Myanmar) matches as a
//! substring, and a character from such a script is a word boundary for every
//! other script. A caseless script has no "capitalised" notion, so its parts
//! are always eligible.
//!
//! A spaced-script part `P` (folded, `n` letters) also matches an inflected
//! word `W` by one of two rules:
//!
//! - a tail: `W` starts with `P` and the rest is one to six letters of the same
//!   script (`Tomin`, `Leolle`, `ரவிக்கு`), for `n ≥ 3`;
//! - a stem: `W` starts with the first `max(3, n−2)` letters of `P`, is between
//!   `n−1` and `n+6` letters long, and changes the ending (`Pekka` → `Pekan`,
//!   Finnish `Virtanen` → `Virtasen` through its own form). For `n == 3` in a
//!   cased script the stem is two letters and `W` is `n` to `n+3` letters.
//!
//! In a cased script a tail or stem must be capitalised, all upper case, or
//! follow a title, so a lower-case word never matches by inflection. A stem is
//! never a match on its own. Attached Hebrew and Arabic prefixes are compiled
//! too, and the Arabic, diacritic-transliteration and Latin-homoglyph folds are
//! symmetric between the entry and the text. A Cyrillic or Greek look-alike folds
//! to Latin only inside a Latin word (`Cаmille`); every other word keeps its
//! letters. A one-part entry with a diacritic (`Bäck`) keeps its own spelling; a
//! spelling its strip or transliteration derives needs a capital.
//!
//! Mounting the recogniser in a [`crate::Registry`] adds its `PERSON` spans to
//! the deterministic pipeline, where the e-mail layer propagates them and the
//! anonymizer masks them like any other value.

// The submodules are private on purpose: every item below is re-exported at
// this path, so `crate::known_names::…` is exactly what it was before the
// split, and no new public path appears.
mod constants;
mod dictionary;
mod error;
mod matching;
mod rule;
mod variants;

#[cfg(test)]
mod tests;

pub use constants::KNOWN_NAMES;
pub use dictionary::NameDictionary;
pub use error::NameDictionaryError;
