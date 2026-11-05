//! A value split across issued parts is still hidden once they are joined, and
//! parts that hide nothing across a seam join exactly as they were issued.
//!
//! Each part passes the gate on its own, so neither part shows the whole value.
//! [`SafeText::join`] reads the joined text again: half an IBAN next to its
//! other half, a card number cut in two, a label in one part and its secret in
//! the next, a URL, an e-mail address or a health term cut at the seam. Every
//! value below is invented. After the join, in Private and in Open mode:
//! * no six characters in a row of a value the gate hides in the whole text
//!   are readable;
//! * a value the whole text shows (open mode leaves an e-mail address, a phone
//!   number, a URL in clear) joins exactly as its parts were issued;
//! * the sentence around the value stays as the whole text keeps it;
//! * every token and marker of the parts is still there, in order.

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::safetext::SafeText;
use kernel_privacy::Gate;

const MODES: [PrivacyMode; 2] = [PrivacyMode::Private, PrivacyMode::Open];

const WITHHELD: &str = "[auxesis: withheld]";

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

/// The seams reproduced on the round-1 join (Private mode, A1): the two parts,
/// and the value that must not show after the join.
const REPROS: &[(&str, &str, &str)] = &[
    (
        "See https://example.com/",
        "private/page now.",
        "https://example.com/private/page",
    ),
    (
        "mail alice@example.com",
        ".fake.com now.",
        "alice@example.com.fake.com",
    ),
    ("Le patient a le cancer du", " sein.", "cancer du sein"),
    ("Il a un cancer du", " colon.", "cancer du colon"),
    ("Elle a la maladie de", " Crohn.", "maladie de Crohn"),
    ("Il a le diabetes de type", " 2.", "diabetes de type 2"),
    (
        "my card is 4000 0012 3456",
        "-7899-1234",
        "4000 0012 3456-7899-1234",
    ),
];

/// `(before, needle, value, after)`: the needle is cut at every position, and
/// no six characters of the value may stay readable where the whole text hides
/// it. IBAN, card, a national ID in each in-scope language (EN, FR, AF, HU, SL,
/// ZH), multi-word health terms, the ordinary kinds open mode leaves in clear
/// (URL, e-mail address, phone number), then six secrets after a label.
/// Checksums hold where the kind has one; the bank code says FAKE.
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
    ("Le patient a le ", "cancer du sein", "cancer du sein", "."),
    ("Il a un ", "cancer du colon", "cancer du colon", "."),
    ("Elle a la ", "maladie de Crohn", "maladie de Crohn", "."),
    ("Il a le ", "diabetes de type 2", "diabetes de type 2", "."),
    ("Il a le ", "diabète de type 2", "diabète de type 2", "."),
    (
        "See ",
        "https://example.com/private/page",
        "https://example.com/private/page",
        " now.",
    ),
    (
        "mail ",
        "alice@example.com.fake.com",
        "alice@example.com.fake.com",
        " now.",
    ),
    (
        "Call me at ",
        "+33 6 12 34 56 78",
        "+33 6 12 34 56 78",
        " today.",
    ),
    (
        "my card is ",
        "4000 0012 3456-7899-1234",
        "4000 0012 3456-7899-1234",
        ".",
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

/// What is wrong with the join of `texts`, each issued on its own, against
/// `whole`, the whole text as the gate issues it: a value the whole text hides
/// that still shows; a value it shows that did not join as issued, when no part
/// masked a piece of it; the text `before` or `after` the value, which the
/// whole text and its part keep and the join does not; a token or marker lost;
/// a join withheld. A gate that refuses a part issues nothing, so nothing can
/// be wrong.
fn problems(gate: &mut Gate, texts: &[&str], case: (&str, &str, &str), whole: &str) -> Vec<String> {
    let (before, value, after) = case;
    let texts = texts.iter().filter(|text| !text.is_empty());
    let Some(parts) = texts
        .map(|text| issue(gate, text))
        .collect::<Option<Vec<_>>>()
    else {
        return Vec::new();
    };
    let issued: Vec<String> = parts.iter().map(|part| part.as_str().into()).collect();
    let joined = SafeText::join(parts);
    let joined = joined.as_str();
    if joined == WITHHELD {
        return vec!["withheld".to_string()];
    }
    let mut found = Vec::new();
    // A part that masked a piece of a value the whole text shows: the join
    // masks the rest, since it cannot tell where the value ends.
    let marked = issued.iter().any(|part| !kept(part).is_empty());
    match readable_run(whole, value) {
        Some(_) if !marked && joined != issued.concat() => {
            found.push(format!("not as issued: {joined:?}"))
        }
        Some(_) => {}
        None => {
            found.extend(readable_run(joined, value).map(|run| format!("{run:?} in {joined:?}")))
        }
    }
    let (first, last) = (&issued[0], &issued[issued.len() - 1]);
    if whole.starts_with(before) && first.starts_with(before) && !joined.starts_with(before) {
        found.push(format!("{before:?} lost in {joined:?}"));
    }
    if whole.ends_with(after) && last.ends_with(after) && !joined.ends_with(after) {
        found.push(format!("{after:?} lost in {joined:?}"));
    }
    let mut rest = joined;
    for token in issued.iter().flat_map(|part| kept(part)) {
        match rest.find(token) {
            Some(at) => rest = &rest[at + token.len()..],
            None => found.push(format!("lost {token:?} in {joined:?}")),
        }
    }
    found
}

/// Every case through one gate, whole and then cut at every position with no
/// separator, a space or a line break, written as its own part or at the end
/// of the first.
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
        let whole = whole.as_str().to_string();
        if mode == PrivacyMode::Private {
            found.extend(readable_run(&whole, value).map(|run| format!("whole: {run:?}")));
        }
        for ((at, _), (seam, glued)) in needle
            .char_indices()
            .skip(1)
            .flat_map(|cut| seams.map(|seam| (cut, seam)))
        {
            let (head, tail) = needle.split_at(at);
            let head = format!("{before}{head}{}", if glued { seam } else { "" });
            let tail = format!("{tail}{after}");
            let texts = [head.as_str(), if glued { "" } else { seam }, tail.as_str()];
            let more = problems(&mut gate, &texts, (before, value, after), &whole);
            let label = format!("{value:?} cut {at} seam {seam:?} {glued}");
            found.extend(
                more.into_iter()
                    .map(|problem| format!("{label}: {problem}")),
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

/// The seams reproduced on the round-1 join: in both modes, the value shows in
/// no six characters in a row where the whole text hides it, and joins as
/// issued where open mode shows it.
#[test]
fn the_reproduced_seams_hide_their_value_in_both_modes() {
    let mut found = Vec::new();
    for mode in MODES {
        let mut gate = gate(mode);
        for &(head, tail, value) in REPROS {
            let whole = issue(&mut gate, &format!("{head}{tail}")).expect("issued");
            let more = problems(&mut gate, &[head, tail], ("", value, ""), whole.as_str());
            let label = format!("{mode:?} {head:?} + {tail:?}");
            found.extend(
                more.into_iter()
                    .map(|problem| format!("{label}: {problem}")),
            );
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// A value cut in three parts, at two positions of its needle with no
/// separator, hides as a value cut in two. The text around it is the two-part
/// sweep's to check: a value read with a seam's blank deleted is masked as the
/// gate reads it there, with a link word the gate takes (`is`).
#[test]
fn a_value_cut_in_three_parts_is_hidden_after_the_join() {
    let mut found = Vec::new();
    for mode in MODES {
        let mut gate = gate(mode);
        for &(before, needle, value, after) in CASES {
            let whole = issue(&mut gate, &format!("{before}{needle}{after}")).expect("issued");
            let cuts: Vec<usize> = needle.char_indices().map(|(at, _)| at).skip(1).collect();
            let step = (cuts.len() / 6).max(1);
            for (index, &first) in cuts.iter().enumerate().step_by(step) {
                for &second in cuts[index + 1..].iter().step_by(step) {
                    let head = format!("{before}{}", &needle[..first]);
                    let tail = format!("{}{after}", &needle[second..]);
                    let texts = [head.as_str(), &needle[first..second], tail.as_str()];
                    let more = problems(&mut gate, &texts, ("", value, ""), whole.as_str());
                    let label = format!("{mode:?} {value:?} cut {first} and {second}");
                    found.extend(
                        more.into_iter()
                            .map(|problem| format!("{label}: {problem}")),
                    );
                }
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// Whole parts, each value inside one part, join exactly as they were issued,
/// whatever two cases meet at the seam and whatever is between them: nothing,
/// a space, a line or a paragraph break. A secret's clause runs to the end of
/// its paragraph in one text, but its part's input ended a sentence, so it is
/// not read on into the next part.
#[test]
fn whole_parts_join_as_they_were_issued() {
    let mut found = Vec::new();
    for mode in MODES {
        let mut gate = gate(mode);
        let wholes: Vec<SafeText> = CASES
            .iter()
            .map(|case| format!("{}{}{}", case.0, case.1, case.3))
            .map(|text| issue(&mut gate, &text).expect("issued"))
            .collect();
        for seam in ["", " ", "\n", "\n\n"] {
            let between = issue(&mut gate, seam);
            for (first, second) in wholes
                .iter()
                .flat_map(|first| wholes.iter().map(move |second| (first, second)))
            {
                let parts: Vec<SafeText> =
                    [Some(first.clone()), between.clone(), Some(second.clone())]
                        .into_iter()
                        .flatten()
                        .collect();
                let issued: String = parts.iter().map(SafeText::as_str).collect();
                let joined = SafeText::join(parts);
                if joined.as_str() != issued {
                    found.push(format!(
                        "{mode:?} seam {seam:?}: {issued:?} became {:?}",
                        joined.as_str()
                    ));
                }
            }
            let parts = wholes
                .iter()
                .flat_map(|whole| [Some(whole.clone()), between.clone()]);
            let parts: Vec<SafeText> = parts.flatten().collect();
            let issued: String = parts.iter().map(SafeText::as_str).collect();
            assert_eq!(
                SafeText::join(parts).as_str(),
                issued,
                "{mode:?} all, seam {seam:?}"
            );
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// Pieces that hide nothing join as their plain concatenation, glued as a
/// system prompt is built: the application's pieces through an open gate, the
/// owner's through the session's gate.
#[test]
fn pieces_that_hide_nothing_join_as_their_concatenation() {
    let app = [
        "\n\n# Skill: ",
        "\n\n",
        "\n\nReply in the language the owner writes in.",
        "\n\n# Tools\n\n",
        "- `",
        "mail_search",
        "` (risk: ",
        "low",
        "): ",
        "Search the mailbox by sender, subject or date.",
        "\n",
        "- `",
        "calendar_add",
        "` (risk: ",
        "medium",
        "): ",
        "Add an event to the calendar.",
        "\n",
    ];
    let owner = [
        "You are Aux, the owner's assistant. Be brief.",
        "Mail",
        "Draft replies in the owner's voice, short and warm.",
        "- `notes_read` (risk: low): Read the owner's notes.\n",
        "\n# Personal details\nPrefers short answers and works mornings.",
    ];
    for mode in MODES {
        let (mut app_gate, mut session) = (gate(PrivacyMode::Open), gate(mode));
        let order = [
            (true, 0),
            (false, 0),
            (true, 0),
            (false, 1),
            (true, 1),
            (false, 2),
        ];
        let mut parts: Vec<SafeText> = Vec::new();
        for (from_app, index) in order {
            let text = if from_app { app[index] } else { owner[index] };
            parts.push(
                issue(
                    if from_app {
                        &mut app_gate
                    } else {
                        &mut session
                    },
                    text,
                )
                .expect("issued"),
            );
        }
        parts.extend(
            app[2..]
                .iter()
                .map(|text| issue(&mut app_gate, text).expect("issued")),
        );
        parts.extend(
            owner[3..]
                .iter()
                .map(|text| issue(&mut session, text).expect("issued")),
        );
        let issued: String = parts.iter().map(SafeText::as_str).collect();
        assert_eq!(SafeText::join(parts).as_str(), issued, "{mode:?}");
    }
}

/// A value of groups that runs on past what the join reads beside a mask
/// withholds the join: its tail would be left in clear. A value of twenty
/// groups cut in the middle is masked in each part and joins as issued.
#[test]
fn a_twenty_group_value_beside_a_mask_withholds_the_join() {
    let groups = ["ABCD", "1234", "EFGH", "5678"].repeat(5).join(" ");
    let digits = ["1234", "5678", "9012", "3456", "7890"].repeat(4);
    for mode in MODES {
        let mut gate = gate(mode);
        let parts = [
            "Ma carte 4000 0012 3456 7899".to_string(),
            format!(" {groups} ok."),
        ];
        let parts = parts.map(|text| issue(&mut gate, &text).expect("issued"));
        assert_eq!(SafeText::join(parts).as_str(), WITHHELD, "{mode:?}");
        let parts = [
            format!("Ref {}", digits[..10].join(" ")),
            format!(" {} ok.", digits[10..].join(" ")),
        ];
        let parts = parts.map(|text| issue(&mut gate, &text).expect("issued"));
        let issued: String = parts.iter().map(SafeText::as_str).collect();
        let joined = SafeText::join(parts);
        assert_eq!(joined.as_str(), issued, "{mode:?}");
        if mode == PrivacyMode::Private {
            assert!(
                readable_run(joined.as_str(), &digits.join(" ")).is_none(),
                "{joined:?}"
            );
        }
    }
}

/// A token-shaped string a user typed in an open-mode part is not a token the
/// kernel minted: the join reads it as text, as the whole text reads it.
#[test]
fn a_typed_token_at_a_seam_is_read_as_text() {
    let mut gate = gate(PrivacyMode::Open);
    let texts = ["card 4000 0012 ", "⟦CREDIT_CARD_345678991234⟧ ok."];
    let whole = issue(&mut gate, &texts.concat()).expect("issued");
    let parts = texts.map(|text| issue(&mut gate, text).expect("issued"));
    assert_eq!(SafeText::join(parts).as_str(), whole.as_str());
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
        assert_eq!(SafeText::join(parts).as_str(), WITHHELD, "{mode:?} {at}");
    }
}
