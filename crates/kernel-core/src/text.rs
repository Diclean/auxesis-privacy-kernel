//! Shared text hygiene: sanitising untrusted text, one-line cleaning, and
//! character-budgeted truncation.
//!
//! Tool output, provider errors, model text and store rows are all *external*
//! input: they can contain ANSI escapes, bidi overrides and zero-width
//! characters that spoof what a human or model sees, and they can be
//! arbitrarily large. These primitives are the single implementation used by
//! `kernel-broker`, the daemon API, the CLI and the UI.

/// The value of one ASCII hex digit, in either case.
///
/// Returns `None` for every other byte. One implementation for the kernel's
/// percent, hex, escape and contact decoders, so they cannot drift on case
/// handling or on the value of a digit.
pub fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Noncharacters: reserved code points that never render (U+FDD0-FDEF and
/// the last two points of every plane).
fn is_noncharacter(c: char) -> bool {
    if matches!(c, '\u{FDD0}'..='\u{FDEF}') {
        return true;
    }
    let cp = c as u32;
    cp >= 0xFFFE && (cp & 0xFFFE) == 0xFFFE
}

/// Characters that are invisible or format-only, and can be used to spoof
/// what a human or model sees.
///
/// This is the one invisible-character table in the kernel. It is the union of
/// the two tables it replaces: the sanitizer's (exotic spaces, bidi controls,
/// fillers, tags) and the contact folder's `Default_Ignorable_Code_Point` set
/// (which additionally holds the Arabic tatweel, U+0640). Every character
/// either old table matched is still matched: the union never drops a range.
///
/// Control characters and noncharacters are deliberately not part of this
/// table: they are separate predicates (`char::is_control` and
/// `is_noncharacter`) that the sanitizer applies on top. U+0640 is in the
/// table for matching, but it is a visible elongation the sanitizer has
/// always kept.
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00A0}' // no-break space
            | '\u{00AD}' // soft hyphen
            | '\u{034F}' // combining grapheme joiner
            | '\u{0600}'..='\u{0605}' // Arabic number signs
            | '\u{061C}' // Arabic letter mark
            | '\u{0640}' // Arabic tatweel (matching only, see above)
            | '\u{06DD}' | '\u{070F}' | '\u{0890}'..='\u{0891}' | '\u{08E2}'
            | '\u{115F}'..='\u{1160}' // Hangul fillers
            | '\u{1680}' // Ogham space mark
            | '\u{17B4}'..='\u{17B5}' // Khmer inherent vowels
            | '\u{180B}'..='\u{180F}' // Mongolian selectors + vowel separator
            | '\u{2000}'..='\u{200F}' // exotic spaces + zero-width joiners/bidi
            | '\u{2028}'..='\u{202F}' // separators + bidi overrides + narrow space
            | '\u{205F}'..='\u{206F}' // no-break space + word joiner/isolates
            | '\u{2800}' // blank braille pattern
            | '\u{3000}' // ideographic space
            | '\u{3164}' // Hangul filler
            | '\u{FE00}'..='\u{FE0F}' // variation selectors
            | '\u{FEFF}' // BOM / zero-width no-break space
            | '\u{FFA0}' // halfwidth Hangul filler
            | '\u{FFF0}'..='\u{FFFB}' // unassigned/DI + interlinear annotations
            | '\u{110BD}' | '\u{110CD}' // Kaithi number signs
            | '\u{13430}'..='\u{1343F}' // Egyptian format controls
            | '\u{1BCA0}'..='\u{1BCA3}' // shorthand format controls
            | '\u{1D173}'..='\u{1D17A}' // musical format controls
            | '\u{E0000}'..='\u{E0FFF}' // tags, VS supplement, DI reserved
    )
}

/// Whether the sanitizer drops `c`: the shared table, minus the one entry only
/// the matchers need (the Arabic tatweel), plus the terminal controls and
/// noncharacters it has always removed.
fn is_stripped(c: char) -> bool {
    (is_invisible(c) && c != '\u{0640}') || c.is_control() || is_noncharacter(c)
}

/// Strip control and invisible characters, keeping only `\n` and `\t`.
pub fn sanitize_text(input: &str) -> String {
    input
        .chars()
        .filter(|c| !is_stripped(*c) || *c == '\n' || *c == '\t')
        .collect()
}

/// The bidi *isolate* controls U+2066–U+2069. Unlike the embedding/override
/// controls around them, isolates wrap a run instead of overriding the whole
/// rest of the line, so they are legitimate mixed-direction content.
fn is_bidi_isolate(c: char) -> bool {
    matches!(c, '\u{2066}'..='\u{2069}')
}

/// Like [`sanitize_text`], but keeps the four bidi isolate controls
/// (U+2066–U+2069) while still dropping every other control/invisible
/// character. Used by the scrub preview path so text that hides no secret
/// keeps those codepoints byte-for-byte (dh-1 fidelity note).
pub fn sanitize_text_keep_bidi_isolates(input: &str) -> String {
    input
        .chars()
        .filter(|c| !is_stripped(*c) || *c == '\n' || *c == '\t' || is_bidi_isolate(*c))
        .collect()
}

/// Sanitize external text and collapse it to one line.
///
/// The canonical `clean_field` every transport (daemon, CLI, app) shares; two
/// copies of a security-relevant sanitiser can drift, one cannot.
pub fn clean_field(raw: &str) -> String {
    sanitize_text(raw)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Cap by characters (never splits UTF-8) and mark the cut.
///
/// `max == 0` yields just the truncation marker; `max == 1` yields `…`.
pub fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_value_reads_both_cases_and_refuses_other_bytes() {
        assert_eq!(hex_value(b'0'), Some(0));
        assert_eq!(hex_value(b'9'), Some(9));
        assert_eq!(hex_value(b'a'), Some(10));
        assert_eq!(hex_value(b'F'), Some(15));
        for byte in [b'g', b'G', b'/', b' ', 0x80, 0xff] {
            assert_eq!(hex_value(byte), None, "0x{byte:02x}");
        }
    }

    #[test]
    fn strips_control_and_invisible_characters() {
        let raw = "safe\u{1b}[31mred\u{0}\u{202e}reversed\u{200b}\u{feff}end";
        let clean = sanitize_text(raw);
        assert!(!clean.contains('\u{1b}'));
        assert!(!clean.contains('\u{202e}'));
        assert!(!clean.contains('\u{200b}'));
        assert!(!clean.contains('\u{feff}'));
        assert_eq!(clean, "safe[31mredreversedend");
    }

    #[test]
    fn strips_extended_invisible_set() {
        let raw = "a\u{00A0}b\u{034F}c\u{0600}d\u{061C}e\u{115F}f\u{1680}g\u{180E}h\u{2003}i\u{2060}j\u{2800}k\u{3000}l\u{3164}m\u{FE0F}n\u{FDD0}o\u{FFA0}p\u{FFF1}q\u{13430}r\u{1BCA0}s\u{1D173}t\u{E0041}u\u{E0090}v\u{E0100}w";
        let clean = sanitize_text(raw);
        assert_eq!(clean, "abcdefghijklmnopqrstuvw");
    }

    #[test]
    fn strips_noncharacters_and_di_reserved() {
        let raw = "a\u{FDD0}b\u{FDEF}c\u{FFFF}d\u{1FFFE}e\u{10FFFF}f\u{E01F0}g\u{E0F00}h";
        let clean = sanitize_text(raw);
        assert_eq!(clean, "abcdefgh");
    }

    #[test]
    fn keeps_newlines_and_tabs() {
        assert_eq!(sanitize_text("a\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn keeps_bidi_isolates_and_strips_the_other_invisibles() {
        let raw = "a\u{2066}b\u{2067}c\u{2068}d\u{2069}e\u{202e}f\u{200b}g\u{1b}h";
        assert_eq!(
            sanitize_text_keep_bidi_isolates(raw),
            "a\u{2066}b\u{2067}c\u{2068}d\u{2069}efgh"
        );
        // The plain sanitizer still drops the isolates (terminal path).
        assert_eq!(sanitize_text("a\u{2066}b\u{2069}c"), "abc");
    }

    #[test]
    fn strips_carriage_returns() {
        assert_eq!(sanitize_text("a\r\nb"), "a\nb");
    }

    #[test]
    fn clean_field_collapses_to_one_sanitized_line() {
        let raw = "  two\nlines\u{200b}\tand   spaces\u{1b}[0m  ";
        assert_eq!(clean_field(raw), "two lines and spaces[0m");
        assert_eq!(clean_field("   "), "");
    }

    #[test]
    fn truncate_chars_never_splits_and_marks_the_cut() {
        assert_eq!(truncate_chars("short", 10), "short");
        assert_eq!(truncate_chars("abcdef", 4), "abc…");
        assert_eq!(truncate_chars("éééé", 2), "é…");
        assert_eq!(truncate_chars("abcdef", 0), "…");
    }

    #[test]
    fn every_stripped_codepoint_is_removed() {
        for cp in 0u32..=0x10FFFF {
            if let Some(c) = char::from_u32(cp) {
                if is_stripped(c) && c != '\n' && c != '\t' {
                    assert!(
                        sanitize_text(&c.to_string()).is_empty(),
                        "U+{cp:04X} survived sanitize_text"
                    );
                }
            }
        }
    }

    #[test]
    fn invisible_table_is_the_union_of_the_two_old_tables() {
        // The two tables as they were before the merge, kept here as the
        // oracle. The sanitizer's control/noncharacter predicates were separate
        // from its range table; the last assertion puts them back so the
        // sanitizer's exact old predicate is pinned too.
        fn old_sanitizer_table(c: char) -> bool {
            matches!(
                c,
                '\u{00A0}'
                    | '\u{00AD}'
                    | '\u{034F}'
                    | '\u{0600}'..='\u{0605}'
                    | '\u{061C}'
                    | '\u{06DD}'
                    | '\u{070F}'
                    | '\u{0890}'..='\u{0891}'
                    | '\u{08E2}'
                    | '\u{115F}'..='\u{1160}'
                    | '\u{1680}'
                    | '\u{17B4}'..='\u{17B5}'
                    | '\u{180B}'..='\u{180F}'
                    | '\u{2000}'..='\u{200F}'
                    | '\u{2028}'..='\u{202E}'
                    | '\u{202F}'
                    | '\u{205F}'
                    | '\u{2060}'..='\u{206F}'
                    | '\u{2800}'
                    | '\u{3000}'
                    | '\u{3164}'
                    | '\u{FE00}'..='\u{FE0F}'
                    | '\u{FEFF}'
                    | '\u{FFA0}'
                    | '\u{FFF0}'..='\u{FFF8}'
                    | '\u{FFF9}'..='\u{FFFB}'
                    | '\u{110BD}'
                    | '\u{110CD}'
                    | '\u{13430}'..='\u{1343F}'
                    | '\u{1BCA0}'..='\u{1BCA3}'
                    | '\u{1D173}'..='\u{1D17A}'
                    | '\u{E0000}'..='\u{E0FFF}'
            )
        }
        fn old_folder_table(c: char) -> bool {
            matches!(
                c,
                '\u{00AD}'
                    | '\u{034F}'
                    | '\u{061C}'
                    | '\u{0640}'
                    | '\u{115F}'..='\u{1160}'
                    | '\u{17B4}'..='\u{17B5}'
                    | '\u{180B}'..='\u{180F}'
                    | '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2060}'..='\u{206F}'
                    | '\u{3164}'
                    | '\u{FE00}'..='\u{FE0F}'
                    | '\u{FEFF}'
                    | '\u{FFA0}'
                    | '\u{FFF0}'..='\u{FFF8}'
                    | '\u{1BCA0}'..='\u{1BCA3}'
                    | '\u{1D173}'..='\u{1D17A}'
                    | '\u{E0000}'..='\u{E0FFF}'
            )
        }

        for cp in 0u32..=0x10FFFF {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            assert_eq!(
                is_invisible(c),
                old_sanitizer_table(c) || old_folder_table(c),
                "U+{cp:04X}: the shared table must be exactly the union"
            );
            let old_sanitizer = old_sanitizer_table(c) || c.is_control() || is_noncharacter(c);
            assert_eq!(
                is_stripped(c),
                old_sanitizer,
                "U+{cp:04X}: the sanitizer predicate changed"
            );
        }

        // The one union-only member is kept by the sanitizer on purpose: it is
        // an Arabic elongation, not a zero-width character.
        assert!(is_invisible('\u{0640}'));
        assert!(!is_stripped('\u{0640}'));
        assert_eq!(sanitize_text("a\u{0640}b"), "a\u{0640}b");
    }

    #[test]
    fn sanitizes_a_megabyte_within_budget() {
        let raw = "abc\u{200B}def\n".repeat(100_000); // ~1 MB
        let started = std::time::Instant::now();
        let clean = sanitize_text(&raw);
        let elapsed = started.elapsed();
        assert!(!clean.contains('\u{200B}'));
        assert!(
            elapsed.as_millis() < 2_000,
            "sanitizing ~1 MB took {elapsed:?}"
        );
    }

    #[test]
    fn injection_corpus_files_are_sanitized() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../qa/attacks/prompt-injection");
        // The attack corpus is private and left out of the public export;
        // a tree without it skips this test (the private tree always has it).
        if !dir.exists() {
            eprintln!("skipped: no attack corpus at {}", dir.display());
            return;
        }
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("corpus dir {}: {err}", dir.display()));
        let mut checked = 0;
        for entry in entries {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("txt") {
                continue;
            }
            let raw = std::fs::read_to_string(&path).unwrap();
            let clean = sanitize_text(&raw);
            assert!(
                !clean
                    .chars()
                    .any(|c| is_stripped(c) && c != '\n' && c != '\t'),
                "{} still contains invisible characters",
                path.display()
            );
            checked += 1;
        }
        assert!(
            checked >= 5,
            "expected seeded corpus files, found {checked}"
        );
    }
}
