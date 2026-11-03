//! NINO-CHAIN pass B: a glued run after a whole head loses no value byte of
//! main.

use super::helpers::{covered, header, parse, read, tails, MODES};

/// Frozen from origin/main (0e6833e7) on the texts of [`glued_runs`].
const GLUED_MAIN: &str = include_str!("../data/nino_chain_glued_main.txt");

/// The parts of one [`glued_runs`] text, as indices into its lists: head,
/// filler, break, next shape, value.
type Key = [usize; 5];

/// The byte ranges of the three values of one [`glued_runs`] text.
type Values = [(usize, usize); 3];

/// Zero to three filler bytes between the head's suffix and the break.
const GLUED_FILLERS: [&str; 4] = ["", "9", "X", "Xq"];

/// Glue, then the breaks the normaliser folds into one separator.
const GLUED_BREAKS: [&str; 6] = ["", " ", "\n", "\r\n", "\t", "\u{2028}"];

/// NINO-CHAIN r2 (pass B): a head with its own suffix, zero to three filler
/// bytes, a break, then a shape with no suffix (`BM085263`) or a whole number,
/// glued to a value the first round masks whole: 5 heads x 4 fillers x 6
/// breaks x 6 shapes x 4 values = 2,880 texts. Each comes with its parts and
/// the byte ranges of its three values (head, next, glued value); the filler
/// and the break are no value. Digits are built from their pairs at run time.
fn glued_runs() -> Vec<(String, Key, Values)> {
    let (a, b) = (["71", "28", "49"], ["08", "52", "63"]);
    let heads = [
        format!("ZK{}{}{}C", a[0], a[1], a[2]),
        format!("ZK {} {} {} C", a[0], a[1], a[2]),
        format!("ZK-{}-{}-{}-C", a[0], a[1], a[2]),
        format!("zk{}{}{}c", a[0], a[1], a[2]),
        format!("ZK/{}/{}/{}/C", a[0], a[1], a[2]),
    ];
    let nexts = [
        format!("BM{}{}{}", b[0], b[1], b[2]),
        format!("CM{}{}{}", b[0], b[1], b[2]),
        format!("bm{}{}{}", b[0], b[1], b[2]),
        format!("BM{}{}{}D", b[0], b[1], b[2]),
        format!("CM {} {} {} A", b[0], b[1], b[2]),
        format!("BM-{}-{}-{}-D", b[0], b[1], b[2]),
    ];
    let [iban, _, key, akia, _] = tails();
    let values = [key, akia, iban, format!("4111{}", "1".repeat(12))];
    let mut out = Vec::new();
    for (h, head) in heads.iter().enumerate() {
        for (f, filler) in GLUED_FILLERS.iter().enumerate() {
            for (r, br) in GLUED_BREAKS.iter().enumerate() {
                for (n, next) in nexts.iter().enumerate() {
                    for (t, value) in values.iter().enumerate() {
                        let text = format!("{head}{filler}{br}{next}{value}");
                        let at = head.len() + filler.len() + br.len();
                        let spans = [
                            (0, head.len()),
                            (at, at + next.len()),
                            (at + next.len(), text.len()),
                        ];
                        out.push((text, [h, f, r, n, t], spans));
                    }
                }
            }
        }
    }
    out
}

/// The texts of [`glued_runs`].
pub(crate) fn glued_texts() -> Vec<String> {
    glued_runs().into_iter().map(|(text, ..)| text).collect()
}

/// The accepted P3 of pass B r1 (TODO 1), closed: Private only, the parts of
/// the text, and the filler bytes main masked that head leaves in clear (a gap
/// letter, a stray digit, a break between two masked numbers). Main masked
/// them only by reading the whole glued run as one IBAN or ID. A loss not in
/// this list, and an entry that no longer happens, both fail the test. Empty:
/// on this corpus the r2 glue rule loses no filler byte either (699b949d lost
/// 20 here, `9`/`X` with their break, besides the two values).
const FILLER_ONLY: &[(Key, &str)] = &[];

/// RED on 699b949d: `ZK712849C9BM085263ghp_…` and `ZK712849C9CM085263ghp_…`
/// left `BM085263` / `CM085263` in clear in Private, where main masked the
/// whole run. Every value byte main masked stays masked in both modes, with no
/// new refusal and nothing unreadable; the only bytes head may leave that main
/// masked are the filler bytes of [`FILLER_ONLY`], exactly.
#[test]
fn a_glued_run_after_a_whole_head_loses_no_value_byte_of_main() {
    let runs = glued_runs();
    assert_eq!(runs.len(), 2_880);
    // Head 0, filler "9", glue, `BM…` / `CM…`, the `ghp_` key.
    assert!(runs[144].0.starts_with("ZK712849C9BM085263ghp_"));
    assert!(runs[148].0.starts_with("ZK712849C9CM085263ghp_"));
    let (head, body) = GLUED_MAIN.split_once('\n').unwrap();
    assert_eq!(head, header(&glued_texts()), "inputs changed: refreeze");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), runs.len());
    let (mut bad, mut filler) = (Vec::new(), Vec::new());
    for ((text, key, spans), record) in runs.iter().zip(records) {
        for (index, was) in record.split('|').map(parse).enumerate() {
            let mode = MODES[index];
            let Some(was) = was else { continue };
            let Some(Some(now)) = read(mode, text) else {
                bad.push(format!("{mode:?} refused or unreadable {text:?}"));
                continue;
            };
            let gone: Vec<usize> = was
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .collect();
            let value = gone
                .iter()
                .filter(|&&b| spans.iter().any(|&(s, e)| s <= b && b < e))
                .count();
            if value > 0 {
                bad.push(format!("{mode:?} lost {value} value bytes in {text:?}"));
            } else if !gone.is_empty() {
                let bytes: String = gone
                    .iter()
                    .map(|&b| std::ascii::escape_default(text.as_bytes()[b]).to_string())
                    .collect();
                if index == 0 {
                    filler.push((*key, bytes));
                } else {
                    bad.push(format!("{mode:?} lost filler {bytes:?} in {text:?}"));
                }
            }
        }
    }
    let listed: Vec<(Key, String)> = FILLER_ONLY
        .iter()
        .map(|(key, bytes)| (*key, (*bytes).to_string()))
        .collect();
    for entry in filler.iter().filter(|entry| !listed.contains(entry)) {
        bad.push(format!(
            "not in FILLER_ONLY: ({:?}, {:?}),",
            entry.0, entry.1
        ));
    }
    for entry in listed.iter().filter(|entry| !filler.contains(entry)) {
        bad.push(format!("FILLER_ONLY entry no longer happens: {entry:?}"));
    }
    eprintln!("{} texts: {} filler-only losses", runs.len(), filler.len());
    let count = bad.len();
    bad.truncate(80);
    assert!(bad.is_empty(), "{count}\n{}", bad.join("\n"));
}
