//! The fixed word lists and the stable recogniser name.

/// The stable recogniser name echoed in [`Span::recognizer`](crate::span::Span::recognizer).
pub const KNOWN_NAMES: &str = "known_names";

/// Titles that release a two-letter part or a particle from the case rule.
pub(super) const TITLES: &[&str] = &[
    "m",
    "mme",
    "mlle",
    "mr",
    "mrs",
    "ms",
    "dr",
    "pr",
    "prof",
    "monsieur",
    "madame",
    "mademoiselle",
    "maitre",
    "herr",
    "frau",
    "sr",
    "sra",
];

/// Particles that name nobody on their own: they match only after a title, and
/// are included when they sit inside a longer matched run.
pub(super) const PARTICLES: &[&str] = &[
    "de", "du", "des", "der", "den", "van", "von", "di", "da", "dos", "das", "del", "della", "le",
    "la", "les", "el", "al", "bin", "ibn", "ben", "ter", "ten", "het", "zu", "op", "ap", "abu",
    "o", "d",
];

/// The Hebrew letters that attach to a name part as a prefix.
pub(super) const HEBREW_PREFIXES: &[&str] = &["ו", "ה", "ב", "כ", "ל", "מ", "ש"];

/// The Arabic compound openers whose spaced and glued spellings both name the
/// same person (`عبد الله` / `عبدالله`).
pub(super) const ARABIC_COMPOUNDS: &[&str] = &["عبد", "ابو", "ابن"];
