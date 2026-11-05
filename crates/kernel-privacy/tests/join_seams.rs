//! `SafeText::join` reads again only the text that crosses a seam: a value cut
//! across two parts stays hidden, and a seam on a blank changes nothing.

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{Gate, SafeText};

const WITHHELD: &str = "[auxesis: withheld]";

/// Cuts with no blank at the seam, as `first|second|value`.
const GLUED: &str = "See https://example.com/|private/page now.|https://example.com/private/page
mail alice@example.com|.fake.com now.|alice@example.com.fake.com
my card is 4000 0012 3456|-7899-1234|4000 0012 3456-7899-1234
My key is s|k-proj-Fake0123456789abcdefghij.|sk-proj-Fake0123456789abcdefghij
Passport P<GBRDOE<|JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<|P<GBRDOE<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<";

/// An IBAN and a card, each cut at every position.
const CUT_EVERYWHERE: &str = "IBAN FR7630006000011234567890189|IBAN GB82WEST12345698765432|\
card 4000001234567899|card 4111-1111-1111-1111";

/// Known limit, as `first|second`: the gate hid the condition or the street in
/// its own part, and what follows the blank is no value on its own.
const LIMITS: &str = "Le patient a le cancer du| sein.
Le patient a un cancer du| colon.
Le patient a la maladie de| Crohn.
Le patient a le diabète de type| 2.
Send it to 10 Downing Street, London| SW1A 2AA today.";

/// Thirty whole values, as `first|second|…`.
const VALUES: &str = "alice@example.com|+33 6 12 34 56 78|https://example.com/private/page|\
FR76 3000 6000 0112 3456 7890 189|4000 0012 3456 7899|cancer du sein|maladie de Crohn|\
10 Downing Street, London SW1A 2AA|sk-proj-Fake0123456789abcdefghij|192.168.1.20|\
P<GBRDOE<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<|Bonjour tout le monde|QQ 12 34 56 C|heart failure|\
2 99 12 75 123 456 31|password: Fake-Pass-42|bob.martin@exemple.fr|+44 20 7946 0958|\
diabète de type 2|12 rue des Lilas, 75011 Paris|GB82 WEST 1234 5698 7654 32|Hello world|\
4111 1111 1111 1111|née le 12/03/1985|www.example.org/page?id=42|Le rendez-vous est à 15 h.|\
ID-nommer 9001015009086|api_key=Fake0123456789abcdef0123|Merci beaucoup|身份证号：110105199003071239";

fn gates() -> [Gate; 2] {
    [PrivacyMode::Private, PrivacyMode::Open].map(|mode| {
        let destination = Destination::Vendor("hosted-model".to_string());
        match admit(PathId::A1, mode, &Context { destination }) {
            Decision::Allow(grant) => Gate::for_grant(&grant, [7; 32]),
            other => panic!("{other:?}"),
        }
    })
}

/// The whole text as `gate` issues it, then its parts issued one by one, as
/// concatenated and as joined.
fn split(gate: &mut Gate, parts: &[impl AsRef<str>]) -> (String, String, String) {
    let mut issue = |text: &str| gate.text(text).unwrap().0;
    let whole = issue(&parts.iter().map(|p| p.as_ref()).collect::<String>());
    let issued: Vec<SafeText> = parts.iter().map(|p| issue(p.as_ref())).collect();
    let concat = issued.iter().map(SafeText::as_str).collect();
    let joined = SafeText::join(issued).as_str().to_string();
    (whole.as_str().into(), concat, joined)
}

/// Whether `text` shows six characters in a row of `value` outside its tokens.
fn readable(text: &str, value: &str) -> bool {
    let mut seen = String::new();
    for piece in text.split('⟦') {
        seen.extend([" ", piece.split_once('⟧').map_or(piece, |(_, rest)| rest)]);
    }
    let six = value.chars().collect::<Vec<_>>();
    six.windows(6).any(|w| seen.contains(&String::from_iter(w)))
}

#[test]
fn a_value_cut_with_no_blank_at_the_seam_stays_hidden() {
    let mut cuts: Vec<Vec<String>> = GLUED
        .lines()
        .map(|line| line.split('|').map(String::from).collect())
        .collect();
    for text in CUT_EVERYWHERE.split('|') {
        for (at, _) in text.char_indices().skip(6) {
            let (first, second) = (text[..at].into(), format!("{} ok", &text[at..]));
            cuts.push(vec![first, second, text[5..].into()]);
        }
    }
    for mut gate in gates() {
        for cut in &cuts {
            let (whole, concat, joined) = split(&mut gate, &cut[..2]);
            let hidden = !readable(&whole, &cut[2]);
            assert!(!hidden || !readable(&joined, &cut[2]), "{cut:?}: {joined}");
            // A token the kernel wrote is never edited.
            for token in concat.split('⟦').skip(1).filter_map(|p| p.split_once('⟧')) {
                assert!(joined == WITHHELD || joined.contains(token.0), "{joined}");
            }
        }
        // A token typed by the user is plain text: it goes with its run.
        let (_, _, joined) = split(&mut gate, &["x ⟦EMAIL_0123456789AB⟧", "Bonjour"]);
        assert!(joined.ends_with("[value removed]") && !joined.contains("EMAIL"));
        // One run, so the word glued to the link goes with it (a trade-off).
        let (_, _, joined) = split(&mut gate, &["See https://example.com/doc", "Hello world."]);
        assert!(joined.ends_with("[value removed] world."), "{joined}");
    }
}

#[test]
fn a_seam_on_a_blank_or_in_clear_text_changes_nothing() {
    let values: Vec<&str> = VALUES.split('|').collect();
    assert_eq!(values.len(), 30);
    let text = "The quarterly review covers budgets and hiring.";
    for mut gate in gates() {
        for (at, _) in text.char_indices().skip(1) {
            let (_, concat, joined) = split(&mut gate, &[&text[..at], &text[at..]]);
            assert_eq!(joined, concat);
        }
        for blank in [" ", "\n"] {
            let glued = values.iter().map(|value| format!("{value}{blank}"));
            let alone = values.iter().flat_map(|v| [v.to_string(), blank.into()]);
            for parts in [glued.collect::<Vec<_>>(), alone.collect()] {
                let (_, concat, joined) = split(&mut gate, &parts);
                assert_eq!(joined, concat);
            }
        }
        for limit in LIMITS.lines() {
            let (_, concat, joined) = split(&mut gate, &limit.split('|').collect::<Vec<_>>());
            assert_eq!(joined, concat);
        }
    }
}

#[test]
fn a_run_past_the_cap_or_a_secret_too_long_withholds_the_join() {
    let (short, long) = ("x".repeat(200), "x".repeat(300));
    let words = format!(" {}", "word ".repeat(250));
    for mut gate in gates() {
        // A run of 400 bytes is read; one of 600 is past the cap.
        assert_eq!(split(&mut gate, &[&short, &short]).2, short.repeat(2));
        assert_eq!(split(&mut gate, &[&long, &long]).2, WITHHELD);
        // A secret line too long for the gate to read withholds the join.
        let parts = ["password: hunter2", &words].map(|p| gate.text(p).unwrap().0);
        assert_eq!(SafeText::join(parts).as_str(), WITHHELD);
    }
}
