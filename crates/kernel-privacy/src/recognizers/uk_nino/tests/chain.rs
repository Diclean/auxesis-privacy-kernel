use super::hits;
use super::UkNinoRecognizer;
use crate::recognizer::Recognizer;

#[test]
fn a_rejected_earlier_shape_does_not_hide_a_nino() {
    assert_eq!(hits("sort code 12-34-56 AB123456C"), vec!["AB123456C"]);
    // `XY 12 34 56 A` is itself a separated shape glued to `B`: it overlaps
    // the compact number and the two are one span (NINO-GLUED-NEXT r1).
    assert_eq!(hits("XY 12 34 56 AB123456C"), vec!["XY 12 34 56 AB123456C"]);
    assert_eq!(hits("QQ 12 34 56 AB123456C"), vec!["QQ 12 34 56 AB123456C"]);
    assert_eq!(hits("code 12 34 56 AB 12 34 56 C"), vec!["AB 12 34 56 C"]);
    assert_eq!(hits("DA 12 34 56 AB 12 34 56 C"), vec!["AB 12 34 56 C"]);
    assert_eq!(hits("id: de 12 34 56 ab123456c"), vec!["ab123456c"]);
}

#[test]
fn a_second_nino_glued_to_letters_after_a_line_break_is_read_whole() {
    assert_eq!(
        hits("AB 12 34 56\nBAB123456B"),
        vec!["AB 12 34 56\nB", "AB123456B"]
    );
}

#[test]
fn a_suffix_glued_to_the_next_line_is_masked_with_the_number() {
    // The glued letter opens the next line, so it is masked with the number
    // and the word is a word again (NINO-GLUED-NEXT).
    assert_eq!(hits("AB 12 34 56\nCblood type A+"), vec!["AB 12 34 56\nC"]);
    assert_eq!(hits("AB123456\nCblood type A+"), vec!["AB123456\nC"]);
    assert_eq!(hits("AB 12 34 56\nC4"), vec!["AB 12 34 56\nC"]);
    // Unless another number starts at that letter: then it is read whole,
    // here with this one, since its own suffix is glued to digits and no
    // pass reads it on its own (FIN-6, NINO-CHAIN r1).
    assert_eq!(
        hits("QQ  12  34  56\nCB 12 34 56 A184127645108946"),
        vec!["QQ  12  34  56\nCB 12 34 56 A"]
    );
}

/// Every shape a number may take, so the suffix letter is kept in all of
/// them and not only where one space or a hyphen separates the pairs
/// (NINO-GLUED-NEXT r1: a second pattern list that knew only those let every
/// other shape lose its first letter, and the number behind it stood in
/// clear). The head is masked too, and where the compact pass keeps the
/// shared letter the two numbers are one span (NINO-CHAIN).
#[test]
fn the_glue_cut_lands_on_every_shape_of_the_next_number() {
    for next in [
        "CB/12/34/56/A",
        "CB.12.34.56.A",
        "CB 12 34 56 A",
        "CB  12  34  56  A",
        "CB   12   34   56   A",
        "CB 12  34 56 A",
        "CB/12/34/56/a",
        "CB-12-34-56-A",
        "CB 12 34 56 a",
        "AB/12/34/56/A",
        "CE/12/34/56/A",
        "CB123456A",
    ] {
        for head in ["AB 12 34 56", "AB-12-34-56", "AB123456", "QQ  12  34  56"] {
            let text = format!("{head}\n{next}");
            let read = UkNinoRecognizer::new().analyze(&text);
            let reach = read.iter().fold(0, |at, span| {
                if span.start <= at {
                    at.max(span.end)
                } else {
                    at
                }
            });
            assert!(
                reach == text.len(),
                "{text:?}: not every byte is masked, only {:?}",
                read.iter()
                    .map(|span| &text[span.start..span.end])
                    .collect::<Vec<_>>()
            );
        }
    }
}

/// A first-pass span must never make an older separated one disappear:
/// `AB 12 34 56 ` and `AB123456\nc` overlap, and dropping the separated span
/// left a whole number in clear (NINO-GLUED-NEXT r1).
#[test]
fn a_first_pass_span_never_suppresses_an_older_separated_one() {
    for text in [
        "AB 12 34 56 AB123456\ncDog walk",
        "AB 12 34 56 AB 12 34 56\ncDog",
        "JG 12 34 56 AB123456\nCblood type A+",
        "QQ  12  34  56  AB123456\nCdog",
    ] {
        let read = UkNinoRecognizer::new().analyze(text);
        // The bytes from 0 to the second number are bytes only the separated
        // pass reads, and the union keeps them: every span starts where the
        // last one ended, and the first one starts at 0.
        assert_eq!(
            read.first().map(|span| span.start),
            Some(0),
            "{text:?}: the first number is not masked at all"
        );
        for pair in read.windows(2) {
            assert_eq!(
                pair[0].end,
                pair[1].start,
                "{text:?}: {:?} to {:?} is in clear",
                &text[pair[0].start..pair[0].end],
                &text[pair[1].start..pair[1].end]
            );
        }
    }
}
