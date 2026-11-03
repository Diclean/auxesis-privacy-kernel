//! Both differentials against origin/main: no byte main masks may be left
//! clear, and no text may be refused.

use super::corpus::documents;
use super::helpers::{covered, header, parse, probe, read, MODES};
use super::targeted::targeted_texts;

/// Frozen from origin/main (0e6833e7) on the corpus of [`documents`].
const MAIN: &str = include_str!("../data/nino_chain_main.txt");

/// Frozen from origin/main (0e6833e7) on the 840 texts of [`targeted`].
const TARGETED_MAIN: &str = include_str!("../data/nino_chain_targeted_main.txt");

/// Every byte `fixture` (frozen on `base`) masked is still masked, in both
/// modes, with no new refusal and no claimed text the reader cannot read back.
fn assert_superset(base: &str, fixture: &str, inputs: &[String]) {
    let (head, body) = fixture.split_once('\n').unwrap();
    assert_eq!(
        head,
        header(inputs),
        "{base}: inputs changed: refreeze on {base}"
    );
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut refused, mut unread, mut grew) = ([0usize; 2], 0, 0, [0usize; 2]);
    let mut lossy = Vec::new();
    for (text, record) in inputs.iter().zip(records) {
        for (index, was) in record.split('|').map(parse).enumerate() {
            let now = read(MODES[index], text);
            if now.is_none() && was.is_some() {
                refused += 1;
                lossy.push(format!("{:?} refused {text:?}", MODES[index]));
                continue;
            }
            let (Some(was), Some(now)) = (was, now) else {
                continue;
            };
            let Some(now) = now else {
                unread += 1;
                lossy.push(format!("{:?} unreadable {text:?}", MODES[index]));
                continue;
            };
            let gone = was
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            if gone > 0 {
                let mode = MODES[index];
                lossy.push(format!("{:?} lost {gone} in {text:?}", mode));
                println!(
                    "DIAG {mode:?} {text:?}\n  main {:?}\n  head {:?}",
                    probe(text, &was),
                    probe(text, &now)
                );
            }
            lost[index] += gone;
            grew[index] += usize::from(now != was);
        }
    }
    eprintln!(
        "{base}: {} texts: bytes lost Private/Open {lost:?}; refusals {refused}; \
         unreadable {unread}; masks changed {grew:?}",
        inputs.len()
    );
    lossy.truncate(40);
    assert_eq!(
        (lost, refused, unread),
        ([0, 0], 0, 0),
        "against {base}:\n{}",
        lossy.join("\n")
    );
}

/// A strict byte superset of origin/main (0e6833e7) on 1,800 documents of NI
/// chains mixed with the other classes, in both modes, with no new refusal.
#[test]
fn the_seeded_chain_differential_loses_no_byte_of_main() {
    let inputs = documents();
    assert!(inputs.len() >= 1_500, "only {} texts", inputs.len());
    assert_superset("main 0e6833e7", MAIN, &inputs);
}

/// A strict byte superset of origin/main (0e6833e7) on the 840 targeted texts
/// of pass A, in both modes, with no new refusal.
#[test]
fn the_targeted_differential_loses_no_byte_of_main() {
    assert_superset("main 0e6833e7", TARGETED_MAIN, &targeted_texts());
}
