use super::hits;

/// ID-LABEL-1: lower case glued, zero-width and doubled separators, and
/// look-alike capitals, each up to its suffix letter.
#[test]
fn loose_spellings_are_read_to_the_suffix() {
    for (text, value) in [
        ("pn 48 15 16 cok", "pn 48 15 16 c"),
        (
            "PN\u{200b}48\u{200b}15\u{200b}16\u{200b}Cok",
            "PN\u{200b}48\u{200b}15\u{200b}16\u{200b}C",
        ),
        ("PN..48..15..16..C", "PN..48..15..16..C"),
        ("РΝ 48 15 16 С).", "РΝ 48 15 16 С"),
        ("NI number: at 12 34 56 cok", "at 12 34 56 c"),
        ("NI number: Rn 18 35 46 bok", "Rn 18 35 46 b"),
        ("NINO - on 12 34 56 dog", "on 12 34 56 d"),
    ] {
        assert_eq!(hits(text), [value], "{text:?}");
    }
}

#[test]
fn a_new_shape_stays_clear_when_it_is_no_nino() {
    for text in [
        "PN/48/15/16/E",
        "PN//48//15//16//C",
        "PN    48    15    16    C",
        "PN/48.15/16/C",
        "PN/48/15/16/C9",
        "9PN/48/15/16/C",
        "refpn 48 15 16 c",
        "table 12 34 56 and",
        // ID-LABEL-1: glued lower case after a short word, a dotted host.
        "at 10 20 30 cats",
        "ab.12.34.56.com",
        "рn 48 15 16 с",
        // Seal A round 1: no explicit NI label right before.
        "at 12 34 56 cok",
        "Rn 18 35 46 bok",
        "ANI number: at 12 34 56 cok",
        "NI number list at 12 34 56 cok",
    ] {
        assert!(hits(text).is_empty(), "{text} is masked");
    }
}
