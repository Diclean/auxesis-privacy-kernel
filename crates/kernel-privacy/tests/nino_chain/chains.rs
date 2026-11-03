//! Chains of two to five numbers, every shape combination for two, and a
//! deterministic walk of the shapes for three to five.

use super::helpers::{
    breaks_for, check, number, GLUE_SAFE, HEADS, HEAD_PREFIXES, LETTERS, PAIRS, PREFIXES, SHAPES,
};

/// Chains of two to five numbers, every shape combination for two, and a
/// deterministic walk of the shapes for three to five, in both modes.
#[test]
fn a_chain_of_two_to_five_numbers_masks_every_one() {
    let mut bad = Vec::new();
    let mut chains: Vec<(String, Vec<String>)> = Vec::new();
    for &a in &SHAPES {
        for &b in &SHAPES {
            for br in ["\n", " ", ""] {
                if br.is_empty() && !(GLUE_SAFE[a] && GLUE_SAFE[b]) {
                    continue;
                }
                let first = number(a, "AB", 0, Some(LETTERS[a % 4]));
                let second = number(b, "CE", 1, Some(LETTERS[(b + 1) % 4]));
                chains.push((format!("{first}{br}{second}"), vec![first, second]));
            }
        }
    }
    for len in 3..=5 {
        for step in 0..288 {
            for suffixless in [false, true] {
                // A head with no suffix letter of its own is only a number when
                // the letter behind it completes it, so it takes the shapes the
                // compact pass reads and the next number's prefix must open
                // with A to D — the letters a suffix may be.
                let pool: &[usize] = if suffixless { &HEADS } else { &SHAPES };
                let prefixes: &[&str] = if suffixless {
                    &HEAD_PREFIXES
                } else {
                    &PREFIXES
                };
                let kinds: Vec<usize> = (0..len)
                    .map(|at| pool[(step * 5 + at * 7 + at * at) % pool.len()])
                    .collect();
                let parts: Vec<String> = kinds
                    .iter()
                    .enumerate()
                    .map(|(at, &kind)| {
                        number(
                            kind,
                            prefixes[(step + at) % prefixes.len()],
                            (step + at) % PAIRS.len(),
                            match suffixless {
                                true if at % 2 == 1 && at + 1 < len => None,
                                _ => Some(LETTERS[(step + at) % 4]),
                            },
                        )
                    })
                    .collect();
                // A head with no suffix letter of its own needs a separator
                // behind it to be read at all, so glue is for whole numbers.
                let list = breaks_for(&kinds, suffixless);
                let text = parts.join(list[(step + 1) % list.len()]);
                chains.push((text, parts));
            }
        }
    }
    for (text, keep) in &chains {
        check(&mut bad, text, keep);
    }
    let count = bad.len();
    bad.truncate(40);
    assert!(bad.is_empty(), "{count}\n{}", bad.join("\n"));
}
