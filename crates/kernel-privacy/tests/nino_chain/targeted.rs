//! NINO-CHAIN pass A: a number the residue round alone reads keeps the letter
//! its suffix opens the next number with.

use super::helpers::{check, tails};

/// NINO-CHAIN r1 (pass A): a head, a break, a next number whose own suffix is
/// glued to a value only the residue round reads it past, then that value:
/// 4 heads x 7 breaks x 6 next numbers x 5 values = 840 texts, each with the
/// head and the next number (built from their digits) to mask whole.
fn targeted() -> Vec<(String, Vec<String>)> {
    let (a, b) = (["67", "18", "39"], ["05", "51", "39"]);
    let heads = [
        format!("ak {} {} {}", a[0], a[1], a[2]),
        format!("AK {} {} {}", a[0], a[1], a[2]),
        format!("ak{}{}{}", a[0], a[1], a[2]),
        format!("AK-{}-{}-{}", a[0], a[1], a[2]),
    ];
    let nexts = [
        format!("bl {} {} {} d", b[0], b[1], b[2]),
        format!("bl{}{}{}d", b[0], b[1], b[2]),
        format!("BL{}{}{}D", b[0], b[1], b[2]),
        format!("BL {} {} {} D", b[0], b[1], b[2]),
        format!("bl-{}-{}-{}-d", b[0], b[1], b[2]),
        format!("BL-{}-{}-{}-D", b[0], b[1], b[2]),
    ];
    let mut out = Vec::new();
    for head in &heads {
        for br in ["\r\n", "\n", " ", "", "\t", "\u{2028}", "\r"] {
            for next in &nexts {
                for tail in tails() {
                    let text = format!("{head}{br}{next}{tail}");
                    out.push((text, vec![head.clone(), next.clone()]));
                }
            }
        }
    }
    out
}

/// The texts of [`targeted`].
pub(crate) fn targeted_texts() -> Vec<String> {
    targeted().into_iter().map(|(text, _)| text).collect()
}

/// RED on c6f901ba (pass A): the head took the next number's first letter even
/// where no pass read that number in the first round, so the residue round
/// could not read it either and `l 05 51 39 d` stood in clear. Both numbers
/// are masked whole in both modes (Open removes a national ID too, and has no
/// residue round), and every text is read back exactly.
#[test]
fn a_next_number_read_only_in_the_residue_round_keeps_its_letter() {
    let cases = targeted();
    assert_eq!(cases.len(), 840);
    let mut bad = Vec::new();
    for (text, keep) in &cases {
        check(&mut bad, text, keep);
    }
    let count = bad.len();
    bad.truncate(40);
    assert!(bad.is_empty(), "{count}\n{}", bad.join("\n"));
}
