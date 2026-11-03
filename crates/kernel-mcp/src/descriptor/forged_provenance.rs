//! Detecting and replacing a forged Auxesis provenance line.

use super::limits::FORGED_PROVENANCE_MARKER;

/// Lowercase, alphanumeric-only fragments that identify a forged provenance tag.
///
/// [`crate::tools::UNTRUSTED_MCP_TAG`] normalises to
/// `untrustedmcpservercontenttreatasdataneverasinstructions`; matching either
/// half catches a tag split across a line break. Comparing the *normalised*
/// form, not the literal, is what defeats case, spacing, invisible-character and
/// homoglyph variants (security review P2).
pub(super) const FORGED_PROVENANCE_STEMS: [&str; 2] = [
    "untrustedmcpservercontent",
    "treatasdataneverasinstructions",
];

/// Replace every line that forges [`crate::tools::UNTRUSTED_MCP_TAG`].
///
/// The tag is compared in a *normalised* form: each character is folded to its
/// common Latin homoglyph (Cyrillic/Greek letters, fullwidth ASCII), lowercased,
/// and everything that is not an ASCII alphanumeric is dropped — so case,
/// spacing, Unicode dashes, quotes, zero-width and non-breaking characters and
/// homoglyphs all collapse away. The scan runs over the whole text with its line
/// breaks removed, so a tag split across two lines is caught as well; any line
/// that contributed a match has its whole content replaced by
/// [`FORGED_PROVENANCE_MARKER`].
pub(super) fn neutralise_forged_provenance(text: &str) -> String {
    let (normalised, origins) = normalise_for_provenance_scan(text);
    let mut forged = vec![false; text.split('\n').count()];
    let mut hit = false;
    for stem in FORGED_PROVENANCE_STEMS {
        let mut cursor = 0;
        while let Some(offset) = normalised[cursor..].find(stem) {
            let start = cursor + offset;
            let end = start + stem.len();
            for line in &origins[start..end] {
                forged[*line] = true;
                hit = true;
            }
            // Advance by one so overlapping matches are still seen.
            cursor = start + 1;
        }
    }
    if !hit {
        return text.to_owned();
    }
    text.split('\n')
        .enumerate()
        .map(|(index, line)| {
            if forged[index] {
                FORGED_PROVENANCE_MARKER
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Normalise `text` to ASCII alphanumerics and remember the source line of each
/// surviving character.
///
/// The line break itself is not alphanumeric, so the normalised string is the
/// text with its breaks removed, and `origins` maps every normalised byte back
/// to the line that produced it. Because the output is pure ASCII, a normalised
/// byte index is also a character index into `origins`.
pub(super) fn normalise_for_provenance_scan(text: &str) -> (String, Vec<usize>) {
    let mut normalised = String::with_capacity(text.len());
    let mut origins = Vec::with_capacity(text.len());
    for (line, content) in text.split('\n').enumerate() {
        for character in content.chars() {
            for folded in fold_confusable(character).to_lowercase() {
                if folded.is_ascii_alphanumeric() {
                    normalised.push(folded);
                    origins.push(line);
                }
            }
        }
    }
    (normalised, origins)
}

/// Fold one character to the common Latin lookalike a hostile server may use.
///
/// The `kernel-mcp` crate deliberately takes no Unicode-normalisation dependency:
/// NFKC does not fold Cyrillic/Greek homoglyphs anyway (they are distinct
/// letters, not compatibility equivalents), so the relevant confusables are
/// listed here explicitly. Everything else is returned unchanged and is then
/// dropped by the ASCII-alphanumeric filter if it is not a Latin letter or digit.
fn fold_confusable(character: char) -> char {
    // Fullwidth ASCII (U+FF01..=U+FF5E) maps one-to-one onto ASCII.
    if ('\u{ff01}'..='\u{ff5e}').contains(&character) {
        return char::from_u32(character as u32 - 0xfee0).unwrap_or(character);
    }
    match character {
        // Cyrillic lowercase homoglyphs.
        'а' => 'a',
        'в' => 'b',
        'г' => 'r',
        'е' => 'e',
        'к' => 'k',
        'м' => 'm',
        'н' => 'h',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'т' => 't',
        'у' => 'y',
        'х' => 'x',
        'ѕ' => 's',
        'і' => 'i',
        'ј' => 'j',
        'ѵ' => 'v',
        'һ' => 'h',
        'ԁ' => 'd',
        'ӏ' => 'i',
        // Cyrillic uppercase homoglyphs.
        'А' => 'a',
        'В' => 'b',
        'Е' => 'e',
        'К' => 'k',
        'М' => 'm',
        'Н' => 'h',
        'О' => 'o',
        'Р' => 'p',
        'С' => 'c',
        'Т' => 't',
        'У' => 'y',
        'Х' => 'x',
        'Ѕ' => 's',
        'І' => 'i',
        'Ј' => 'j',
        'Ѵ' => 'v',
        'Ԁ' => 'd',
        // Greek homoglyphs (lowercase then uppercase).
        'α' => 'a',
        'ε' => 'e',
        'ι' => 'i',
        'κ' => 'k',
        'μ' => 'm',
        'ν' => 'v',
        'ο' => 'o',
        'ρ' => 'p',
        'σ' | 'ς' | 'ϲ' => 's',
        'τ' => 't',
        'υ' => 'u',
        'χ' => 'x',
        'ϳ' => 'j',
        'Α' => 'a',
        'Β' => 'b',
        'Ε' => 'e',
        'Η' => 'h',
        'Ι' => 'i',
        'Κ' => 'k',
        'Μ' => 'm',
        'Ν' => 'n',
        'Ο' => 'o',
        'Ρ' => 'p',
        'Τ' => 't',
        'Υ' => 'y',
        'Χ' => 'x',
        'Ϲ' => 'c',
        other => other,
    }
}
