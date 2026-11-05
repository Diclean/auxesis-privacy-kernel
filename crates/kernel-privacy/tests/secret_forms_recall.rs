//! KV02-SECRETS acceptance: common secret forms are hidden in Private and in
//! Open mode, and hard look-alikes keep their text.
//!
//! A value is hidden only when no 6-character run of it (the whole value when
//! shorter) is readable in the gate's output; a refusal is a miss. The forms
//! are issuer key prefixes, cues in EN/FR/AF/HU/SL/ZH, `.env` lines, connection
//! strings, headers, command lines, key blocks, seed phrases and a few others.
//! Every value is invented (`data/secret_forms_cases.rs`).

use std::collections::BTreeMap;

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{EntityKind, Gate};
use regex::Regex;

mod cases {
    include!("data/secret_forms_cases.rs");
}

const MODES: [PrivacyMode; 2] = [PrivacyMode::Private, PrivacyMode::Open];

/// The gate's output, the same with each token and `[… removed]` marker blanked
/// to one `\u{FFFC}`, and the number of secrets it reported; `None` for a refusal.
fn issue(mode: PrivacyMode, text: &str) -> Option<(String, String, usize)> {
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &ctx) else {
        panic!("A1 must be allowed in {mode:?}");
    };
    let mut gate = Gate::for_grant(&grant, [5u8; 32]);
    let (safe, report) = gate.text(text).ok()?;
    let mut blanked = safe.as_str().to_string();
    for (token, _) in gate.take_minted() {
        blanked = blanked.replace(&token, "\u{FFFC}");
    }
    let marker = Regex::new(r"\[[^\[\]\n]* removed\]").expect("marker shape");
    let blanked = marker.replace_all(&blanked, "\u{FFFC}").into_owned();
    let secrets = report.count(EntityKind::Secret);
    Some((safe.as_str().to_string(), blanked, secrets))
}

/// The first 6-character run of `value` (the whole value when shorter) in `text`.
fn readable_run(text: &str, value: &str) -> Option<String> {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 6 {
        return text.contains(value).then(|| value.to_string());
    }
    let mut runs = chars.windows(6).map(|run| run.iter().collect::<String>());
    runs.find(|run| text.contains(run.as_str()))
}

#[test]
fn the_set_is_large_enough_and_covers_six_languages() {
    let positives = cases::positives();
    assert!(positives.len() >= 120 && cases::negatives().len() >= 60);
    for form in ["cue-en", "cue-fr", "cue-af", "cue-hu", "cue-sl", "cue-zh"] {
        assert!(positives.iter().filter(|case| case.0 == form).count() >= 10);
    }
    // No run of a value may also stand in its carrier text, or a hidden value
    // would read as a leak.
    for (form, text, values) in &positives {
        let carrier = values.iter().fold(text.clone(), |text, value| {
            text.replacen(value.as_str(), "\u{FFFC}", 1)
        });
        let repeated = values
            .iter()
            .find(|value| readable_run(&carrier, value).is_some());
        assert!(repeated.is_none(), "{form}: {text:?} repeats {repeated:?}");
    }
}

#[test]
fn common_secret_forms_are_hidden_in_both_modes() {
    let mut misses = Vec::new();
    let mut per_form: BTreeMap<(&str, String), (usize, usize)> = BTreeMap::new();
    for (form, text, values) in &cases::positives() {
        for mode in MODES {
            let tally = per_form.entry((*form, format!("{mode:?}"))).or_default();
            tally.1 += 1;
            let Some((_, blanked, _)) = issue(mode, text) else {
                misses.push(format!("{form} {mode:?} refused {text:?}"));
                continue;
            };
            let leaks: Vec<String> = values
                .iter()
                .filter_map(|value| readable_run(&blanked, value))
                .collect();
            if leaks.is_empty() {
                tally.0 += 1;
            } else {
                misses.push(format!(
                    "{form} {mode:?} {text:?}: {leaks:?} in {blanked:?}"
                ));
            }
        }
    }
    let mut totals: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for ((form, mode), (hidden, all)) in &per_form {
        eprintln!("{form} {mode}: {hidden}/{all}");
        let total = totals.entry(mode.as_str()).or_default();
        total.0 += hidden;
        total.1 += all;
    }
    for (mode, (hidden, all)) in totals {
        eprintln!("{mode}: {hidden}/{all} positives hidden");
    }
    assert!(
        misses.is_empty(),
        "{} misses:\n{}",
        misses.len(),
        misses.join("\n")
    );
}

#[test]
fn hard_negatives_keep_their_text_in_both_modes() {
    let negatives = cases::negatives();
    let mut wrong = Vec::new();
    for text in &negatives {
        for mode in MODES {
            match issue(mode, text) {
                None => wrong.push(format!("{mode:?} refused {text:?}")),
                Some((output, _, secrets))
                    if secrets > 0 || mode == PrivacyMode::Open && output != *text =>
                {
                    wrong.push(format!(
                        "{mode:?} {text:?} -> {output:?} ({secrets} secrets)"
                    ));
                }
                Some(_) => {}
            }
        }
    }
    let clear = 2 * negatives.len() - wrong.len();
    eprintln!("negatives clear: {clear}/{}", 2 * negatives.len());
    assert!(
        wrong.is_empty(),
        "{} masked:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
