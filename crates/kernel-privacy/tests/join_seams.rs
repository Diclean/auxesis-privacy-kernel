//! `SafeText::join` reads every seam again: a value cut across two parts stays
//! hidden wherever the whole text hides it, and a join that finds nothing new
//! is the concatenation of its parts, byte for byte.

use kernel_core::privacy::PrivacyMode::{Open, Private};
use kernel_core::privacy::{admit, Context, Decision, Destination, PathId};
use kernel_privacy::{Gate, SafeText};

const WITHHELD: &str = "[auxesis: withheld]";

/// Texts cut at every position of a stretch, as `text|stretch|value`; the value
/// that must stay hidden is the stretch when it is left out.
const CUTS: &str = "the password: hunter2|: hunter2|hunter2
password: hunter2 ok|password|hunter2 ok
password: Fake-Pass-42|password|Fake-Pass-42
password: Fake-Pass-42Bonjour tout le monde|2B|Fake-Pass-42Bonjour tout le monde
Authorization: Bearer FakeToken12345678|Authorization|FakeToken12345678
my card is 4000 0012 3456 7899|4000 0012 3456 7899
my card is 4000 0012 3456-7899-1234|-7899|4000 0012 3456-7899-1234
IBAN FR76 3000 6000 0112 3456 7890 189 ok|FR76 3000 6000 0112 3456 7890 189
IBAN GB82 WEST 1234 5698 7654 32 ok|GB82 WEST 1234 5698 7654 32
call +33 6 12 34 56 78|+33 6 12 34 56 78
Le patient a le cancer du sein.|cancer du sein
Le patient a un cancer du colon.| colon|cancer du colon
Le patient a la maladie de Crohn.| Crohn|maladie de Crohn
Le patient a le diabète de type 2.| 2|diabète de type 2
Send it to 10 Downing Street, London SW1A 2AA today.|London SW1A 2AA|10 Downing Street, London SW1A 2AA
Écrire au 12 rue de la Paix, 75002 Paris.| Paix|12 rue de la Paix, 75002 Paris
See https://example.com/private/page now.|/private|https://example.com/private/page
See www.example.org/page?id=42&ref=mail now.|?id|www.example.org/page?id=42&ref=mail
mail alice@example.com.fake.com now.|.fake|alice@example.com.fake.com
My key is sk-proj-Fake0123456789abcdefghij.|sk-|sk-proj-Fake0123456789abcdefghij
Passport P<GBRDOE<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<|<JOHN|P<GBRDOE<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<";

/// Thirty plain parts, none of them a value.
const PLAIN: &str = "Hello|world|Bonjour tout le monde|Merci beaucoup|The quarterly review|\
covers budgets and hiring.|Le rendez-vous est à 15 h.|See you at 10|Room 12|page 3 of 7|ok|42|\
Paris|London|rue|de la|password|Authorization|card|IBAN|call me|today.|2026|v1.2.3|x|\
Thanks a lot|N°|—|(see below)|Notes:";

fn gates() -> [(&'static str, Gate); 2] {
    [("Private", Private), ("Open", Open)].map(|(name, mode)| {
        let destination = Destination::Vendor("hosted-model".to_string());
        match admit(PathId::A1, mode, &Context { destination }) {
            Decision::Allow(grant) => (name, Gate::for_grant(&grant, [7; 32])),
            other => panic!("{other:?}"),
        }
    })
}

/// The whole text as `gate` issues it (or [`WITHHELD`] when it refuses it),
/// then its parts issued one by one, as concatenated and as joined.
fn split(gate: &mut Gate, parts: &[&str]) -> [String; 3] {
    let mut issue = |text: &str| gate.text(text).map(|issued| issued.0);
    let text = |issued: SafeText| issued.as_str().to_string();
    let whole = issue(&parts.concat()).map_or(WITHHELD.to_string(), text);
    let issued: Vec<_> = parts.iter().map(|p| issue(p).expect("issued")).collect();
    let concat = issued.iter().map(SafeText::as_str).collect();
    [whole, concat, text(SafeText::join(issued))]
}

/// The six-character runs of `value` that `whole` hides and `joined` shows.
fn leaks(whole: &str, joined: &str, value: &str) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    let runs = chars.windows(6).map(String::from_iter);
    runs.filter(|run| !whole.contains(run) && joined.contains(run))
        .collect()
}

#[test]
fn a_value_cut_at_a_seam_stays_hidden_where_the_whole_hides_it() {
    let mut failures = Vec::new();
    for (name, mut gate) in gates() {
        for line in CUTS.lines() {
            let cut: Vec<&str> = line.split('|').collect();
            let (text, value) = (cut[0], cut.get(2).unwrap_or(&cut[1]));
            let from = text.find(cut[1]).expect("the stretch is in the text");
            for at in (from..=from + cut[1].len()).filter(|&at| text.is_char_boundary(at)) {
                let parts = [&text[..at], &text[at..]];
                let [whole, concat, joined] = split(&mut gate, &parts);
                let shown = leaks(&whole, &joined, value);
                if !shown.is_empty() || joined == WITHHELD {
                    failures.push(format!(
                        "{name} {parts:?}\n  whole  {whole}\n  concat {concat}\n  joined {joined}\n  shows  {shown:?}"
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_join_that_finds_nothing_new_is_the_concatenation() {
    let plain: Vec<&str> = PLAIN.split('|').collect();
    let sentence = "The quarterly review covers budgets and hiring.";
    let mut failures = Vec::new();
    for (name, mut gate) in gates() {
        // Only where the whole text finds nothing either, unless `always`.
        let mut same = |parts: &[&str], always: bool| {
            let [whole, concat, joined] = split(&mut gate, parts);
            if (always || whole == concat) && joined != concat {
                failures.push(format!("{name} {parts:?}: {concat:?} -> {joined:?}"));
            }
        };
        for (at, _) in sentence.char_indices() {
            same(&[&sentence[..at], &sentence[at..]], true);
        }
        for &first in &plain {
            for second in &plain {
                for blank in ["", " ", "\n"] {
                    same(&[first, format!("{blank}{second}").as_str()], false);
                }
            }
        }
        // A marker or token a user typed is plain text, never eaten.
        same(&["Ref [card removed]", "2026 ok"], true);
        same(&["Bonjour [card removed]", "4000 0012 3456 7899"], true);
        same(&["x ⟦EMAIL_0123456789AB⟧", "Bonjour"], false);
        // Open shows links in clear, so the word glued to one stays.
        let open = name == "Open";
        same(&["See https://example.com/doc", "Hello world."], open);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_value_past_the_widest_window_or_a_long_run_on_a_token_withholds_the_join() {
    let (words, short, long) = (" word".repeat(250), "x".repeat(300), "x".repeat(600));
    for (name, mut gate) in gates() {
        // The secret's clause runs on past the widest window; a long run is no
        // value; glued to a token past 512 bytes, it withholds (Open shows links).
        let joins = [
            ["password: hunter2", words.as_str()],
            [short.as_str(), short.as_str()],
            ["See https://example.com/", long.as_str()],
        ]
        .map(|parts| {
            let [_, concat, joined] = split(&mut gate, &parts);
            (joined == WITHHELD, joined == concat)
        });
        let private = name == "Private";
        let expected = [(true, false), (false, true), (private, !private)];
        assert_eq!(joins, expected, "{name}");
    }
}
