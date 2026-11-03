//! Pin, table and property tests for the secret-link scanner.

use super::*;

#[test]
fn the_pins_stay_clear_and_the_link_window_is_96_effective_bytes() {
    for text in CLEAR
        .iter()
        .chain(&["|   | password |\n|---|---|\n| bank |    |"])
    {
        assert_eq!(link_scan(text), [], "{text}");
    }
    for form in ["\u{E000}", "\u{FFFD}", "x"] {
        let text = |n: usize| format!("password for {} is hunter2 horse", form.repeat(n));
        let (fits, over) = (text(88), text(89));
        assert_eq!(
            link_scan(&fits),
            [(fits.len() - 13, fits.len())],
            "B5 88 {form:?}"
        );
        assert_eq!(link_scan(&over), [], "B5 89 {form:?}");
    }
}

#[test]
fn p7_every_case_keeps_main_masking() {
    for &(_, text, _, _) in CASES.iter().chain(PR1B_CASES).chain(PR2_CASES) {
        p1_and_p7(text).unwrap();
    }
    built_cases()
        .iter()
        .for_each(|case| p1_and_p7(&case.1).unwrap());
    refusal_cases()
        .iter()
        .for_each(|case| p1_and_p7(&case.1).unwrap());
    owned_cells()
        .iter()
        .for_each(|(text, _)| p4(text, &[]).unwrap());
}

/// P2-1: a pipe-free delimiter adds no span where no table rule applies.
#[test]
fn a_text_with_no_table_keeps_its_spans() {
    for text in PR2_SAME {
        assert_eq!(scan(text, true), scan(text, false), "{text:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p1_spans_are_well_formed(tokens in prop::collection::vec(prop::sample::select(ALPHABET), 0..600)) {
        let text: String = tokens.concat();
        let text = &text[..text.floor_char_boundary(4096)];
        p1_and_p7(text)?;
    }

    #[test]
    fn p7_a_planted_text_keeps_main_masking((text, _, _) in planted()) {
        p1_and_p7(&text)?;
    }

    #[test]
    fn p1_and_p7_hold_on_owned_texts((text, _, _) in owned()) {
        p1_and_p7(&text)?;
    }

    #[test]
    fn p4_tables_only_add_spans((text, hide) in tables()) {
        p4(&text, &hide)?;
    }

    /// P4 on texts of pipes, dashes, keys and quotes, with no table promised.
    #[test]
    fn p4_pipe_texts_only_add_spans(tokens in prop::collection::vec(prop::sample::select(ALPHABET), 0..600)) {
        let text: String = tokens.concat();
        p4(&text[..text.floor_char_boundary(4096)], &[])?;
    }

    #[test]
    fn p6_a_sentinel_reads_as_x(tokens in prop::collection::vec(prop::sample::select(ALPHABET), 0..600)) {
        let text: String = tokens.concat();
        p6(&text[..text.floor_char_boundary(4096)])?;
    }

    /// P6 at the caps: Entry keys of 63–66 and link windows of 95–98 effective bytes.
    #[test]
    fn p6_holds_at_the_caps(forms in prop::collection::vec(prop::sample::select(&["\u{E000}", "\u{FFFD}", "x"][..]), 87..=90), shape in 0..3usize) {
        let run = forms[24..].concat();
        let text = match shape {
            0 => format!("password: red horse\n\"{run}\": ok"),
            1 => format!("password: red horse\n{run}: ok"),
            _ => format!("password for {} is hunter2 horse", forms.concat()),
        };
        p6(&text)?;
    }
}
