use proptest::strategy::Strategy as _;

use super::folded;

/// The full trim/filter/lowercase body, kept as the oracle for the ASCII
/// fast path.
fn folded_reference(cell: &str, wide: bool) -> String {
    let cell = cell.trim().trim_matches('"');
    let cell = if wide {
        cell.trim_end_matches([':', ' ', '\t', '\u{a0}', '\u{202f}'])
    } else {
        cell
    };
    cell.chars()
        .filter(|ch| !matches!(ch, '_' | '-' | ' '))
        .filter(|&ch| !wide || !matches!(ch, '\u{a0}' | '\u{202f}' | '\u{300}'..='\u{36f}'))
        .flat_map(char::to_lowercase)
        .collect()
}

#[test]
fn folded_ascii_fast_path_matches_the_unicode_path_on_edges() {
    for (cell, wide) in [
        ("", false),
        (" Password ", false),
        ("PASSWORD\t", false),
        ("\"Mot de passe :\"", true),
        ("CLÉ PRIVÉE", true),
        ("Clé\u{300} privée", true),
        ("\u{202f}pin\u{202f}", true),
        ("Full\u{ff11}\u{ff21}", true),
        ("zero\u{200b}width", false),
        ("中文", true),
    ] {
        assert_eq!(
            folded(cell, wide),
            folded_reference(cell, wide),
            "{cell:?} {wide}"
        );
    }
}

/// Every ASCII byte, alone and in short mixed cells, under both header
/// lists: the fast branch is covered by enumeration, not by a strategy.
#[test]
fn folded_ascii_fast_path_matches_every_byte() {
    for byte in 0x00u8..=0x7f {
        let ch = char::from(byte);
        for cell in [
            ch.to_string(),
            format!(" {ch} "),
            format!("\"{ch}\":"),
            format!("A{ch}z 9"),
        ] {
            for wide in [false, true] {
                assert_eq!(
                    folded(&cell, wide),
                    folded_reference(&cell, wide),
                    "{cell:?} {wide}"
                );
            }
        }
    }
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

    #[test]
    fn folded_fast_path_matches_the_unicode_path(
        cell in folded_text(),
        wide in proptest::prelude::any::<bool>(),
    ) {
        proptest::prop_assert_eq!(
            folded(&cell, wide),
            folded_reference(&cell, wide),
            "{:?} wide={}",
            cell,
            wide
        );
    }
}

/// ASCII, mixed and non-ASCII cells: quotes, trimmed delimiters, accents,
/// invisibles and full-width forms.
fn folded_text() -> impl proptest::strategy::Strategy<Value = String> {
    proptest::collection::vec(
        proptest::prop_oneof![
            proptest::prelude::any::<char>(),
            proptest::sample::select(vec![
                ' ', '\t', '"', ':', '_', '-', '\u{a0}', '\u{202f}', '\u{e9}', '\u{301}',
                '\u{200b}', '\u{200d}', '\u{feff}', '\u{ff11}', '\u{ff21}', '\u{4e2d}',
            ]),
        ],
        0..40,
    )
    .prop_map(|chars| chars.into_iter().collect())
}
