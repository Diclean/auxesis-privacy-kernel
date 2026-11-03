//! NI-shaped prose: no new mask on it, so it must read exactly what main
//! reads, byte for byte.

use super::helpers::{header, number, read, record_of, MODES};

/// NI-shaped prose that reads as a sentence: a flight number, an order line, a
/// part number, a table of figures. A number that opens a line or a word here
/// must keep reading as prose and not gain a second token.
pub(crate) fn prose() -> Vec<String> {
    let mut out = Vec::new();
    let spaced = |prefix| number(0, prefix, 0, None);
    let compact = number(1, "AB", 0, None);
    for br in ["\n", " ", "\r\n"] {
        let heads = [
            format!("Flight {}", spaced("BA")),
            format!("Order {compact}"),
            format!("Part no {}", number(2, "AB", 0, None)),
        ];
        for head in heads {
            for tail in [
                "Cat sat on it",
                "dispatched",
                "in stock",
                "Card payment taken",
                "Dog walk booked",
            ] {
                out.push(format!("{head}{br}{tail}"));
            }
        }
        for tail in [
            format!("ref {} ok", number(3, "CB", 0, Some('A'))),
            "total 42.00 due".to_string(),
            "see the table below".to_string(),
            format!("Item {} added", number(0, "AB", 0, Some('C'))),
        ] {
            out.push(format!("NI number {}{br}{tail}", spaced("AB")));
            out.push(format!("NINO {compact}{br}{tail}"));
        }
    }
    out
}

/// Frozen from origin/main (0e6833e7) on the corpus of [`prose`]: the header
/// (count and hash, so an edit to `prose()` asks for a refreeze), then one
/// record per text.
const PROSE_MAIN: &str = include_str!("../data/nino_chain_prose_main.txt");

/// NI-shaped prose: no new mask on it, so head must read exactly what main
/// reads, byte for byte, in both modes.
#[test]
fn ni_shaped_prose_keeps_the_mask_it_had_on_main() {
    let mut bad = Vec::new();
    let (head, body) = PROSE_MAIN.split_once('\n').unwrap();
    assert_eq!(
        head,
        header(&prose()),
        "inputs changed: refreeze the prose fixture"
    );
    let records: Vec<&str> = body.lines().collect();
    assert_eq!(records.len(), prose().len(), "refreeze the prose fixture");
    for (text, record) in prose().into_iter().zip(records) {
        for (index, &mode) in MODES.iter().enumerate() {
            let was = record.split('|').nth(index).unwrap();
            let got = record_of(&read(mode, &text));
            if got != was {
                bad.push(format!("{mode:?} {text:?}: main {was}, head {got}"));
            }
        }
    }
    let count = bad.len();
    bad.truncate(40);
    assert!(bad.is_empty(), "{count}\n{}", bad.join("\n"));
}
