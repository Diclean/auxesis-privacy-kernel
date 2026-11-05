//! A value split across two issued parts is still hidden once they are joined.
//!
//! Each part passes the gate on its own, so neither part shows the whole value.
//! [`SafeText::join`] reads the joined text again: half an IBAN next to its
//! other half, a card number cut in two, a label in one part and its secret in
//! the next, an ID cut over two lines. Every value below is invented, and no
//! six characters of it in a row may be readable after the join, in Private
//! and in Open mode.

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::safetext::SafeText;
use kernel_privacy::Gate;

const MODES: [PrivacyMode; 2] = [PrivacyMode::Private, PrivacyMode::Open];

/// How many of the [`CASES`], the last ones, are secrets after a label.
const SECRETS: usize = 6;

fn gate(mode: PrivacyMode) -> Gate {
    let destination = Destination::Vendor("hosted-model".to_string());
    let Decision::Allow(grant) = admit(PathId::A1, mode, &Context { destination }) else {
        panic!("A1 is admitted in {mode:?}");
    };
    Gate::for_grant(&grant, [5u8; 32])
}

/// Issue `text`; `None` when the gate refuses it (nothing leaves, so nothing
/// can leak).
fn issue(gate: &mut Gate, text: &str) -> Option<SafeText> {
    gate.text(text).ok().map(|(safe, _)| safe)
}

/// `(before, needle, value, after)`: the needle is cut at every position, and
/// no six characters of the value may stay readable. IBAN, card, a national ID
/// in each in-scope language (EN, FR, AF, HU, SL, ZH), multi-word health
/// terms, then [`SECRETS`] secrets after a label. Checksums hold where the kind
/// has one; the bank code says FAKE.
const CASES: &[(&str, &str, &str, &str)] = &[
    (
        "Please wire it to ",
        "GB77 FAKE 1234 5612 3456 78",
        "GB77 FAKE 1234 5612 3456 78",
        " by Friday.",
    ),
    (
        "Ma carte ",
        "4000 0012 3456 7899",
        "4000 0012 3456 7899",
        " est bloquée.",
    ),
    (
        "Mon numéro de sécurité sociale est ",
        "2 99 12 75 123 456 31",
        "2 99 12 75 123 456 31",
        ".",
    ),
    (
        "My National Insurance number is ",
        "QQ 12 34 56 C",
        "QQ 12 34 56 C",
        ".",
    ),
    ("My ID-nommer is ", "9001015009086", "9001015009086", "."),
    ("A TAJ számom ", "123 456 788", "123 456 788", "."),
    ("Moj ", "EMŠO: 0101990500003", "0101990500003", "."),
    (
        "我的",
        "身份证号：110105199003071239",
        "110105199003071239",
        "。",
    ),
    (
        "He was treated for ",
        "heart failure",
        "heart failure",
        " in May.",
    ),
    (
        "Elle a fait une ",
        "fausse couche",
        "fausse couche",
        " en mars.",
    ),
    (
        "Ima ",
        "sladkorna bolezen",
        "sladkorna bolezen",
        " že leta.",
    ),
    ("The ", "password: Fake-Pass-42", "Fake-Pass-42", " works."),
    (
        "Le ",
        "mot de passe : Faux-Code-42",
        "Faux-Code-42",
        " marche.",
    ),
    ("A ", "jelszó: Hamis-Kod-42", "Hamis-Kod-42", " jó."),
    ("Moje ", "geslo: Lazno-Geslo-42", "Lazno-Geslo-42", " dela."),
    ("Die ", "wagwoord: Vals-Kode-42", "Vals-Kode-42", " werk."),
    ("我的", "密码：Fake-Mima-42", "Fake-Mima-42", "。"),
];

/// The tokens and markers of `text`, in order: `⟦…⟧` and `[…]` (no case writes
/// a bracket of its own).
fn kept(text: &str) -> Vec<&str> {
    let close = |open: &str| if open == "[" { "]" } else { "⟧" };
    let found = text.match_indices(['⟦', '[']).filter_map(|(at, open)| {
        let end = at + text[at..].find(close(open))? + close(open).len();
        Some(&text[at..end])
    });
    found.collect()
}

/// The first run of six characters of `value` that `text` still shows; a
/// token's hex is no value.
fn readable_run(text: &str, value: &str) -> Option<String> {
    let tokens = kept(text).into_iter().filter(|kept| kept.starts_with('⟦'));
    let text = tokens.fold(text.to_string(), |text, token| text.replacen(token, "", 1));
    let chars: Vec<char> = value.chars().collect();
    let mut runs = chars.windows(6).map(|run| run.iter().collect::<String>());
    runs.find(|run| text.contains(run.as_str()))
}

/// Every case through one gate, whole and then cut at every position with no
/// separator, a space or a line break, written as its own part or at the end
/// of the first: what still shows, and any token or marker the join lost.
fn leaks(mode: PrivacyMode) -> Vec<String> {
    let mut gate = gate(mode);
    let mut found = Vec::new();
    let seams = [
        ("", false),
        (" ", false),
        (" ", true),
        ("\n", false),
        ("\n", true),
    ];
    for &(before, needle, value, after) in CASES {
        let whole = issue(&mut gate, &format!("{before}{needle}{after}")).expect("issued");
        found.extend(readable_run(whole.as_str(), value).map(|run| format!("whole: {run:?}")));
        for ((at, _), (seam, glued)) in needle
            .char_indices()
            .skip(1)
            .flat_map(|cut| seams.map(|seam| (cut, seam)))
        {
            let (head, tail) = needle.split_at(at);
            let head = format!("{before}{head}{}", if glued { seam } else { "" });
            let texts = [
                head.as_str(),
                if glued { "" } else { seam },
                &format!("{tail}{after}"),
            ];
            let texts = texts.into_iter().filter(|text| !text.is_empty());
            let Some(parts) = texts
                .map(|text| issue(&mut gate, text))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            let issued: Vec<String> = parts.iter().map(|part| part.as_str().into()).collect();
            let joined = SafeText::join(parts);
            let (joined, mut rest) = (joined.as_str(), joined.as_str());
            for token in issued.iter().flat_map(|part| kept(part)) {
                match rest.find(token) {
                    Some(at) => rest = &rest[at + token.len()..],
                    None => found.push(format!("lost {token:?} in {joined:?}")),
                }
            }
            let shown = readable_run(joined, value).map(|run| format!("{run:?} in {joined:?}"));
            found.extend(
                shown.map(|run| format!("{value:?} cut {at} seam {seam:?} {glued}: {run}")),
            );
        }
    }
    found
}

#[test]
fn a_value_cut_across_a_seam_is_hidden_after_the_join_in_private_mode() {
    let found = leaks(PrivacyMode::Private);
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn a_value_cut_across_a_seam_is_hidden_after_the_join_in_open_mode() {
    let found = leaks(PrivacyMode::Open);
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// Whole parts, each value inside one part, join exactly as they were issued:
/// the join masks only what a seam cuts. A secret's clause runs on to the end
/// of its paragraph, as the gate reads it in one text, so a sentence glued
/// after a secret is hidden too: the secrets join as their own paragraphs.
#[test]
fn whole_parts_join_as_they_were_issued() {
    let plain = &CASES[..CASES.len() - SECRETS];
    for (mode, (seam, cases)) in MODES.into_iter().flat_map(|mode| {
        [("", plain), (" ", plain), ("\n", plain), ("\n\n", CASES)].map(|seam| (mode, seam))
    }) {
        let mut gate = gate(mode);
        let texts = cases
            .iter()
            .flat_map(|case| [format!("{}{}{}", case.0, case.1, case.3), seam.into()]);
        let parts: Vec<SafeText> = texts.filter_map(|text| issue(&mut gate, &text)).collect();
        let issued: String = parts.iter().map(SafeText::as_str).collect();
        assert_eq!(
            SafeText::join(parts).as_str(),
            issued,
            "{mode:?} seam {seam:?}"
        );
    }
}

/// A secret too long for the gate to read, which only a seam shows, is
/// refused as the gate refuses one: the join issues nothing of its parts.
#[test]
fn a_secret_past_the_read_cap_across_a_seam_withholds_the_join() {
    let value = format!("A1{}", "Fake".repeat(300));
    for (mode, at) in MODES.into_iter().flat_map(|mode| [(mode, 0), (mode, 2)]) {
        let mut gate = gate(mode);
        let parts = [
            format!("My password is {}", &value[..at]),
            value[at..].to_string(),
        ];
        let parts = parts.map(|text| issue(&mut gate, &text).expect("issued"));
        assert_eq!(
            SafeText::join(parts).as_str(),
            "[auxesis: withheld]",
            "{mode:?} {at}"
        );
    }
}
