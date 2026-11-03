//! The prefix family: one invented key per prefix, glued after a letter, a
//! digit or `_`.

use kernel_core::privacy::PrivacyMode;

use super::helpers::{covered, exact, issue, keys, parse, restore, MODES};

/// What a key is glued after: letters, digits and `_`.
const GLUES: &[&str] = &["note", "Key", "x", "token", "2024", "7", "_", "my_", "Ab1_"];

/// Where the glued key sits: line start, mid-line, after a break.
pub(crate) const FRAMES: &[&str] = &[
    "{}",
    "{} is the key",
    "Use {} now.",
    "first line\n{} x",
    "first line\r\n  {}",
    "a: {}, b",
];

/// `(text, key start, key end)` for every prefix, glue and frame.
pub(crate) fn positives() -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    for (n, glue) in GLUES.iter().enumerate() {
        for (f, frame) in FRAMES.iter().enumerate() {
            for (_, key) in keys((n * 31 + f) as u64) {
                let (head, tail) = frame.split_once("{}").expect("frame");
                let start = head.len() + glue.len();
                out.push((format!("{head}{glue}{key}{tail}"), start, start + key.len()));
            }
        }
    }
    out
}

/// The repros (round 1), keys invented and built at runtime.
#[test]
fn pass_a_repros_are_hidden_in_both_modes() {
    let sk = |rest: &str| format!("s{}-{rest}", "k");
    let marker = ["T3Blbk", "FJ"].concat();
    let cases = [
        (
            "cfg: key",
            sk("jUBwx48Yl1z2zsQNpa8WqelGdIc5Dl69QisaqTsFhAkVtBnv"),
            "",
        ),
        (
            "The key is 7",
            sk("NuFuI6mfg9SoqdZ7n4ozEiNaLivAo0nFpqlEqCpDxDji2tor"),
            " for prod.",
        ),
        (
            "first line\napiKey",
            sk(&format!("xcgKuaZv3jWzLzUym1Li{marker}ukeKqwo811bw4zWtfVas")),
            "\nnext line",
        ),
        (
            "cfg: z9",
            sk(&format!("aks9wxdUz98SghzRqpOf{marker}bmHaLv5nXj2kmFhGf361")),
            "",
        ),
        ("note", sk("5acc6fab1b3d993596e3bcd1df39067a"), ""),
        (
            "note",
            sk(&format!(
                "or-{}-{}",
                "v1", "79bece22ff98e1753abe9cd1944d9e6a61489c30c95100eb4c6a71c1e30b63a5"
            )),
            "",
        ),
    ];
    for (head, key, tail) in cases {
        let text = format!("{head}{key}{tail}");
        for mode in MODES {
            let now = exact(mode, &text);
            assert!(
                covered(&parse(&now), head.len(), head.len() + key.len()),
                "{mode:?} {text:?}: {now}"
            );
        }
    }
}

#[test]
fn glued_prefixed_keys_are_hidden_in_both_modes() {
    let all = positives();
    let mut wrong = Vec::new();
    for (text, start, end) in &all {
        for mode in MODES {
            let now = exact(mode, text);
            if !covered(&parse(&now), *start, *end) {
                wrong.push(format!("{mode:?} {text:?}: {now}"));
            }
        }
        let (output, minted) = issue(PrivacyMode::Private, text).expect("issued");
        if restore(&output, &minted) != *text {
            wrong.push(format!("restore {text:?} -> {output:?}"));
        }
    }
    assert!(all.len() >= 1_000, "1,000+ positives: {}", all.len());
    let shown: Vec<&String> = wrong.iter().take(30).collect();
    assert!(wrong.is_empty(), "{} wrong:\n{shown:#?}", wrong.len());
}
