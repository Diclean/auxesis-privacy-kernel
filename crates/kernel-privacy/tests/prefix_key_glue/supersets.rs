//! The frozen fixture of main: the head must be a strict byte superset of
//! it.

use kernel_privacy::recognizers::iban::uuid_tokens;

use super::corpus::{header, inputs, negatives, FIXTURE};
use super::helpers::{covered, exact, parse, HEX, MODES};

/// An accepted over-mask (security review, round 1): a random 32-hex or
/// 48-character ID glued after `sk-` (`task-<hex>`, `disk-<id>`) reads as a
/// DeepSeek or OpenAI legacy key. Round 2: the same 32 or 48 characters
/// followed by `-` or `_` and more (`task-<hex>-v2`, `disk-<id>_old`) are the
/// same over-mask.
fn accepted_overmask(text: &str) -> bool {
    text.match_indices("sk-").any(|(at, _)| {
        let run: String = text[at + 3..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
            .collect();
        let cut = |n: usize| {
            (run.len() == n || (run.len() > n && matches!(run.as_bytes()[n], b'-' | b'_')))
                .then(|| &run[..n])
        };
        cut(32).is_some_and(|head| head.bytes().all(|b| HEX.contains(&b)))
            || run
                .get(..48)
                .is_some_and(|head| head.bytes().all(|b| b.is_ascii_alphanumeric()))
    })
}

fn frozen() -> Vec<(String, Vec<String>)> {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').expect("fixture header");
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let split = |r: &str| r.split('|').map(String::from).collect();
    inputs
        .into_iter()
        .zip(records.into_iter().map(split))
        .collect()
}

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    let inputs = inputs();
    let each = |text: &String| MODES.map(|mode| exact(mode, text)).join("|");
    let records: Vec<String> = inputs.iter().map(each).collect();
    let lines: Vec<String> = records.chunks(64).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// The UUID bytes main masked as an IBAN in the look-alikes and the head gives
/// back, Private and Open (IBAN-UUID-OVERMASK).
const GIVEN_BACK_PRIVATE: usize = 1144;
const GIVEN_BACK_OPEN: usize = 1768;

/// A strict byte superset of main in both modes: no byte main masked is clear,
/// no new refusal, every output reads back exactly, and no look-alike text
/// gains a mask, except the accepted over-mask of [`accepted_overmask`], which
/// is counted and printed.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let main = frozen();
    let negatives = negatives();
    let (mut lost, mut refused, mut unaligned, mut grew) = ([0usize; 2], 0, 0, [0usize; 2]);
    let (mut lookalikes, mut accepted) = (0, [0usize; 2]);
    let mut given_back = [0usize; 2];
    for (text, records) in &main {
        for (index, mode) in MODES.into_iter().enumerate() {
            let before = records[index].as_str();
            let now = exact(mode, text);
            if now == "?" || before == "?" {
                unaligned += 1;
                eprintln!("unaligned {mode:?} {text:?}: main {before} now {now}");
            } else if now == "!" {
                refused += usize::from(before != "!");
            } else {
                let (r, ids) = (parse(&now), uuid_tokens(text));
                let (back, gone): (Vec<usize>, Vec<usize>) = parse(before)
                    .iter()
                    .flat_map(|&(s, e)| s..e)
                    .filter(|&b| !covered(&r, b, b + 1))
                    .partition(|&b| negatives.contains(text) && covered(&ids, b, b + 1));
                let only_back = !back.is_empty() && gone.is_empty() && {
                    let old = parse(before);
                    r.iter().all(|&(s, e)| covered(&old, s, e))
                };
                given_back[index] += back.len();
                let gone = gone.len();
                let changed = now != before && negatives.contains(text);
                let allowed = changed && (accepted_overmask(text) || only_back);
                accepted[index] += usize::from(allowed);
                let lookalike = changed && !allowed;
                if gone > 0 || changed {
                    eprintln!("{mode:?} {text:?}: main {before} now {now}");
                }
                lost[index] += gone;
                grew[index] += usize::from(now != before);
                lookalikes += usize::from(lookalike);
            }
        }
    }
    eprintln!(
        "{} inputs ({} negatives): bytes lost Private/Open {lost:?}; new refusals {refused}; \
         unaligned {unaligned}; texts with new masks Private/Open {grew:?}; look-alikes \
         changed {lookalikes}; accepted over-masks Private/Open {accepted:?}; UUID bytes \
         given back Private/Open {given_back:?}",
        main.len(),
        negatives.len()
    );
    assert!(main.len() >= 1_500 + 1_000 && negatives.len() >= 1_200);
    assert_eq!((lost, refused, unaligned, lookalikes), ([0, 0], 0, 0, 0));
    // Only the look-alike UUIDs main read as IBANs go back, and only them: a
    // new loss on a UUID-shaped value moves this count.
    assert_eq!(given_back, [GIVEN_BACK_PRIVATE, GIVEN_BACK_OPEN]);
}
