//! The three leaks of NINO-CHAIN over every shape of a number and every
//! break.

use super::helpers::{
    check, number, BARE_HEADS, BREAKS, GLUE_SAFE, KINDS, LETTERS, SEPARATED, SHAPES, WHOLE_HEADS,
};

/// The three leaks, each over every shape of the number that follows, over
/// every break, with and without a suffix letter on the first number. Each row
/// is the text and the numbers in it that must be masked whole.
fn repros() -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for br in BREAKS {
        // Bug 1: a head with no suffix of its own before a number that opens
        // with its suffix letter, in lower case (which the FIN-6 cut cannot
        // see) and in capitals. Glue needs a head that ends on its digits.
        for (head_kind, prefix) in BARE_HEADS {
            for &kind in &SHAPES {
                if br.is_empty() && (SEPARATED[kind] || SEPARATED[head_kind]) {
                    continue;
                }
                for next_prefix in ["cb", "CB"] {
                    let head = number(head_kind, prefix, 0, None);
                    let next = number(kind, next_prefix, 1, Some('a'));
                    out.push((format!("{head}{br}{next}"), vec![head, next]));
                }
            }
        }
        // Bug 2: the middle number of a chain of three, in every pair of shapes.
        for &a in &SHAPES {
            for &b in &SHAPES {
                let last = (a + b) % KINDS;
                if br.is_empty() && !(GLUE_SAFE[a] && GLUE_SAFE[b] && GLUE_SAFE[last]) {
                    continue;
                }
                let first = number(a, "AB", 0, Some(LETTERS[a % 4]));
                let mid = number(b, "CE", 1, Some(LETTERS[(b + 1) % 4]));
                let last = number(last, "JG", 2, Some(LETTERS[(b + 2) % 4]));
                out.push((
                    format!("{first}{br}{mid}{br}{last}"),
                    vec![first.clone(), mid.clone(), last.clone()],
                ));
            }
        }
        // Bug 3: the number starts one letter behind the glued suffix. The head
        // may stand on its own digits ([`BARE_HEADS`]) or close with a suffix
        // letter of its own ([`WHOLE_HEADS`]). A slashed or dotted head that
        // stands on its digits cannot take a suffix across a break at all — its
        // fourth boundary has to be its own separator — on any base, so it is
        // not here; and it cannot take one under glue either, where there is no
        // boundary at all. The lower-case slashed shape is not here at all: the
        // letter this row glues in front of it makes it a word
        // (`Bab/65/43/21/b`), and a lower-case separated shape written onto a
        // letter is not a number on any base (see [`GLUE_SAFE`]).
        for &kind in &SHAPES {
            if !GLUE_SAFE[kind] {
                continue;
            }
            let bare = BARE_HEADS.map(|(kind, prefix)| number(kind, prefix, 0, None));
            let whole = WHOLE_HEADS.map(|(kind, prefix)| number(kind, prefix, 0, Some('C')));
            for (head, is_bare) in bare
                .into_iter()
                .zip([true; 6])
                .chain(whole.into_iter().zip([false; 6]))
            {
                if br.is_empty() && is_bare {
                    continue;
                }
                let next = number(kind, "AB", 1, Some('B'));
                let text = format!("{head}{br}B{next}");
                out.push((text, vec![head, next]));
            }
        }
    }
    out
}

/// RED on main 041c9c46: the three leaks, over every shape and break, in both
/// modes. Every number of the chain is masked whole.
#[test]
fn every_number_of_a_chain_stays_masked() {
    let mut bad = Vec::new();
    for (text, keep) in repros() {
        check(&mut bad, &text, &keep);
    }
    let count = bad.len();
    bad.truncate(40);
    assert!(bad.is_empty(), "{count}\n{}", bad.join("\n"));
}
