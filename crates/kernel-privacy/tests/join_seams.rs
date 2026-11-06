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
Passport P<GBRDOE<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<|<JOHN|P<GBRDOE<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<
Company number 12345678|1
Adószám: 12345678-2-42|1
VAT reg no: GB 123 4567 89|1";

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

/// A fake private key (base64 of a fixed phrase) after a line of prose: framed
/// with a short last line, and headerless in twelve lines and a short last
/// one before another.
fn keys() -> [String; 2] {
    let first = "MIIEvQIBADANRkFLRSBLRVkgRk9SIFRFU1RTIE9OTFkgRkFLRSBLRVkgRk9SIFRF";
    let line = "U1RTIE9OTFkgRkFLRSBLRVkgRk9SIFRFU1RTIE9OTFkgRkFLRSBLRVkgRk9SIFRF";
    let framed = format!("-----BEGIN PRIVATE KEY-----\n{first}\n{line}\n{line}\nQUJD\n");
    let framed = format!("My key:\n{framed}-----END PRIVATE KEY-----");
    let headerless = format!(
        "My key:\n{first}\n{}\nQUJD\n(That was all.)",
        [line; 11].join("\n")
    );
    [framed, headerless]
}

/// The words (runs of letters and digits) of `text`, each token and marker a blank.
fn clear_words(text: &str) -> Vec<String> {
    let (mut clear, mut rest) = (String::new(), text);
    while let Some(open) = rest.find(['⟦', '[']) {
        clear.push_str(&rest[..open]);
        let close = ['⟧', ']'][usize::from(rest[open..].starts_with('['))];
        let end = rest[open..]
            .find(close)
            .map(|len| open + len + close.len_utf8());
        let mark = end.filter(|&end| {
            let mark = &rest[open..end];
            close == '⟧' || mark == WITHHELD || mark.ends_with(" removed]")
        });
        let next = open + rest[open..].chars().next().map_or(1, char::len_utf8);
        clear.push_str(mark.map_or(&rest[open..next], |_| " "));
        rest = &rest[mark.unwrap_or(next)..];
    }
    clear.push_str(rest);
    let words = clear.split(|ch: char| !ch.is_alphanumeric());
    words
        .filter(|word| !word.is_empty())
        .map(String::from)
        .collect()
}

/// The words `joined` shows in clear that are a word, or a piece of one, that
/// `whole` hides: the value must be absent whole, not only in long runs.
fn shown_pieces(text: &str, whole: &str, joined: &str) -> Vec<String> {
    let kept = clear_words(whole);
    let words = text.split(|ch: char| !ch.is_alphanumeric());
    let hidden: Vec<&str> = words
        .filter(|word| word.chars().count() > 1 && !kept.iter().any(|kept| kept == word))
        .collect();
    let shown = clear_words(joined).into_iter().filter(|word| {
        word.chars().count() > 1
            && !kept.contains(word)
            && hidden.iter().any(|w| w.contains(word.as_str()))
    });
    shown.collect()
}

#[test]
fn a_value_cut_anywhere_stays_hidden_whole_where_the_whole_text_hides_it() {
    let mut failures = Vec::new();
    for (name, mut gate) in gates() {
        let texts = CUTS
            .lines()
            .map(|line| (line.split('|').next().unwrap_or(line).to_string(), false));
        for (text, may_withhold) in texts.chain(keys().map(|key| (key, true))) {
            let whole = gate
                .text(&text)
                .map_or(WITHHELD.to_string(), |i| i.0.as_str().to_string());
            let cuts: Vec<usize> = (1..text.len())
                .filter(|&at| text.is_char_boundary(at))
                .collect();
            // Two parts at every cut; three on a grid of about 24 cuts.
            let grid: Vec<usize> = cuts
                .iter()
                .copied()
                .step_by(cuts.len().div_ceil(24))
                .collect();
            let mut splits: Vec<Vec<usize>> = cuts.iter().map(|&at| vec![at]).collect();
            for (i, &first) in grid.iter().enumerate() {
                splits.extend(grid[i + 1..].iter().map(|&second| vec![first, second]));
            }
            if let Some(at) = text.find(" Downing") {
                splits.push(vec![at, text.find(" SW1A").expect("postcode")]);
            }
            if text.contains("BEGIN") {
                splits.push(vec![text.find("QUJD").expect("last line") - 1]);
            }
            for seams in splits {
                let ends: Vec<usize> = [0].into_iter().chain(seams).chain([text.len()]).collect();
                let parts: Vec<&str> = ends.windows(2).map(|at| &text[at[0]..at[1]]).collect();
                // A part the gate refuses leaves nothing to join.
                let Some(issued) = parts
                    .iter()
                    .map(|part| gate.text(part).ok().map(|i| i.0))
                    .collect::<Option<Vec<_>>>()
                else {
                    continue;
                };
                let joined = SafeText::join(issued).as_str().to_string();
                let shown = shown_pieces(&text, &whole, &joined);
                if !shown.is_empty() || (joined == WITHHELD && !may_withhold) {
                    failures.push(format!(
                        "{name} {parts:?}\n  whole  {whole}\n  joined {joined}\n  shows  {shown:?}"
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_join_of_three_plain_parts_or_prose_beside_a_value_is_the_concatenation() {
    let (sentence, [key, _]) = ("The quarterly review covers budgets and hiring.", keys());
    let mut failures = Vec::new();
    for (name, mut gate) in gates() {
        let cuts: Vec<usize> = (1..sentence.len()).step_by(2).collect();
        for (i, &first) in cuts.iter().enumerate() {
            for &second in &cuts[i + 1..] {
                let parts = [
                    &sentence[..first],
                    &sentence[first..second],
                    &sentence[second..],
                ];
                let [_, concat, joined] = split(&mut gate, &parts);
                if joined != concat {
                    failures.push(format!("{name} {parts:?}: {concat:?} -> {joined:?}"));
                }
            }
        }
        // Prose beside a key, an address (either side) or a number is no key
        // line, no address word and no group: only where the whole text agrees.
        let beside = [
            ["password: hunter2", "\nThanks a lot, see you."],
            ["password: hunter2 ", "\nsee you at noon."],
            ["Send it to 10 Downing Street", " today at noon."],
            ["Meeting With Jean Dupont At", " 10 Downing Street"],
            ["Meet at 10 Downing Street", " Thanks Jean."],
            [key.as_str(), "\n(That was all.)"],
        ];
        for parts in beside {
            let [whole, concat, joined] = split(&mut gate, &parts);
            if whole == concat && joined != concat {
                failures.push(format!("{name} {parts:?}: {concat:?} -> {joined:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
