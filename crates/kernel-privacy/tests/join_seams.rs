//! `SafeText::join` reads every seam again: a value cut across two parts stays
//! hidden wherever the whole text hides it, and a join that finds nothing new
//! is the concatenation of its parts, byte for byte.

use std::collections::HashMap;

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
/// `whole` hides, one character long too.
fn shown_pieces(text: &str, whole: &str, joined: &str) -> Vec<String> {
    let kept = clear_words(whole);
    let words = text.split(|ch: char| !ch.is_alphanumeric());
    let hidden: Vec<&str> = words
        .filter(|word| !word.is_empty() && !kept.iter().any(|kept| kept == word))
        .collect();
    let shown = clear_words(joined)
        .into_iter()
        .filter(|word| !kept.contains(word) && hidden.iter().any(|w| w.contains(word.as_str())));
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

/// A table of 16-character base64 lines is no key: cut in half at a line
/// break, it joins as a key never would, and still hides an IBAN row.
#[test]
fn a_base64_table_cut_at_a_line_break_joins() {
    let table = "0123456789abcdef\n".repeat(100);
    let iban = "0123456789abcdef\n".repeat(9) + "FR7630006000011234567890189\n";
    for (name, mut gate) in gates() {
        let (head, tail) = table.split_at(table.len() / 2);
        let [whole, _, joined] = split(&mut gate, &[head, tail]);
        assert_eq!(joined, whole, "{name}");
        let ruled = format!("----\n{head}");
        let [whole, _, joined] = split(&mut gate, &[&ruled, tail]);
        assert_eq!(joined, whole, "{name} under a rule");
        let text = iban.repeat(10);
        let at = text.len() / 2 + text[text.len() / 2..].find("FR76").expect("row") + 9;
        let (head, tail) = text.split_at(at);
        let [whole, _, joined] = split(&mut gate, &[head, tail]);
        let shown = shown_pieces(&text, &whole, &joined);
        assert!(
            joined != WITHHELD && shown.is_empty(),
            "{name} {joined} {shown:?}"
        );
    }
}

/// The fixed corpus the oracles read: each text of `CUTS` cut in the middle of
/// its stretch, prose beside a value, the keys cut before their short last
/// line, and addresses that end with a city or a brand.
fn corpus() -> Vec<Vec<String>> {
    let mut corpus: Vec<Vec<String>> = CUTS
        .lines()
        .map(|line| {
            let cut: Vec<&str> = line.split('|').collect();
            let mut at = cut[0].find(cut[1]).expect("stretch") + cut[1].len() / 2;
            while !cut[0].is_char_boundary(at) {
                at += 1;
            }
            vec![cut[0][..at].to_string(), cut[0][at..].to_string()]
        })
        .collect();
    let beside = [
        "password: hunter2|\nThanks a lot, see you.",
        "password: hunter2 |\nsee you at noon.",
        "Send it to 10 Downing Street| today at noon.",
        "Meeting With Jean Dupont At| 10 Downing Street",
        "Meet at 10 Downing Street| Thanks Jean.",
        "Write to 12 rue de la Paix| Lyon today.",
        "Write to 12 rue de la Paix| Lille.",
        "Ship to 5 High Street| Uber Orange.",
    ];
    corpus.extend(beside.map(|parts| parts.split('|').map(String::from).collect()));
    for key in keys() {
        let at = key.rfind("QUJD").expect("last line") - 1;
        corpus.push(vec![key[..at].to_string(), key[at..].to_string()]);
    }
    // Tables cut in half: hex lines, a rule above them, a secret column.
    let (hex, rows) = (
        "0123456789abcdef\n".repeat(50),
        "0123456789abcdef,fedcba9876543210\n".repeat(50),
    );
    for (head, tail) in [(hex.clone(), hex.clone()), (format!("----\n{hex}"), hex)] {
        corpus.push(vec![head, tail]);
    }
    corpus.push(vec![format!("id,password\n{rows}"), rows]);
    corpus
}

/// A corpus case's name in [`MAIN_JOINS`]: the mode, the seam and the text's start.
fn case(name: &str, parts: &[&str]) -> String {
    let start: String = parts.concat().chars().take(32).collect();
    format!("{name} {} {}", parts[0].len(), start.replace('\n', "⏎"))
}

/// Main's join (9376e38) of each corpus case, by its [`case`] name, tokens as `⟦⟧`.
const MAIN_JOINS: &str = "Private 16 the password: hunter2 => the password: [secret removed]
Private 4 password: hunter2 ok => password: [secret removed]
Private 4 password: Fake-Pass-42 => password: [secret removed]
Private 22 password: Fake-Pass-42Bonjour to => password: ⟦⟧[value removed] [secret removed]
Private 6 Authorization: Bearer FakeToken1 => Authorization: Bearer [secret removed]
Private 20 my card is 4000 0012 3456 7899 => my card is [card removed]
Private 27 my card is 4000 0012 3456-7899-1 => my card is ⟦⟧[id removed]
Private 21 IBAN FR76 3000 6000 0112 3456 78 => [value removed] ⟦⟧⟦⟧ ok
Private 18 IBAN GB82 WEST 1234 5698 7654 32 => [value removed] ⟦⟧⟦⟧ ok
Private 13 call +33 6 12 34 56 78 => call [value removed]
Private 23 Le patient a le cancer du sein. => Le patient a le ⟦⟧ [health removed].
Private 28 Le patient a un cancer du colon. => Le patient a un ⟦⟧ [health removed].
Private 29 Le patient a la maladie de Crohn => Le patient a la ⟦⟧[value removed]
Private 33 Le patient a le diabète de type  => Le patient a le ⟦⟧ [health removed].
Private 37 Send it to 10 Downing Street, Lo => Send it to ⟦⟧[address removed] ⟦⟧ today.
Private 25 Écrire au 12 rue de la Paix, 750 => Écrire au ⟦⟧[value removed] ⟦⟧.
Private 27 See https://example.com/private/ => See ⟦⟧[value removed] now.
Private 25 See www.example.org/page?id=42&r => See www.example.org/page?id=42&ref=mail now.
Private 24 mail alice@example.com.fake.com  => mail ⟦⟧[value removed] now.
Private 11 My key is sk-proj-Fake0123456789 => My key is [value removed]⟦⟧[value removed]
Private 19 Passport P<GBRDOE<JOHN<<<<<<<<<< => Passport [value removed]⟦⟧
Private 15 Company number 12345678 => Company number [id removed]
Private 11 Adószám: 12345678-2-42 => Adószám: ⟦⟧
Private 15 VAT reg no: GB 123 4567 89 => VAT reg no: [value removed] ⟦⟧
Private 17 password: hunter2⏎Thanks a lot,  => password: ⟦⟧ [secret removed]
Private 18 password: hunter2 ⏎see you at no => password: ⟦⟧  [secret removed]
Private 28 Send it to 10 Downing Street tod => Send it to ⟦⟧ today at noon.
Private 27 Meeting With Jean Dupont At 10 D => Meeting With Jean Dupont At ⟦⟧
Private 25 Meet at 10 Downing Street Thanks => Meet at ⟦⟧ Thanks Jean.
Private 26 Write to 12 rue de la Paix Lyon  => Write to ⟦⟧ Lyon today.
Private 26 Write to 12 rue de la Paix Lille => Write to ⟦⟧ Lille.
Private 21 Ship to 5 High Street Uber Orang => Ship to ⟦⟧ [address removed]
Private 230 My key:⏎-----BEGIN PRIVATE KEY-- => My key: ⟦⟧ [secret removed] [secret removed]
Private 787 My key:⏎MIIEvQIBADANRkFLRSBLRVkg => My key: ⟦⟧⟦⟧⟦⟧⟦⟧⟦⟧⟦⟧⟦⟧ [secret removed] (That was all.)
Private 850 0123456789abcdef⏎0123456789abcde => ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef 
Private 855 ----⏎0123456789abcdef⏎0123456789 => ---- ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef ⟦⟧abcdef 
Private 1712 id,password⏎0123456789abcdef,fed => id,password ⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧,⟦⟧ ⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba⟦⟧abcdef,fedcba9876543210 
Open 16 the password: hunter2 => the password: [secret removed]
Open 4 password: hunter2 ok => password: [secret removed]
Open 4 password: Fake-Pass-42 => password: [secret removed]
Open 22 password: Fake-Pass-42Bonjour to => password: [secret removed][value removed] [secret removed]
Open 6 Authorization: Bearer FakeToken1 => Authorization: Bearer [secret removed]
Open 20 my card is 4000 0012 3456 7899 => my card is [card removed]
Open 27 my card is 4000 0012 3456-7899-1 => my card is 4000 0012 3456-7899-1234
Open 21 IBAN FR76 3000 6000 0112 3456 78 => [value removed] [iban removed][id removed] ok
Open 18 IBAN GB82 WEST 1234 5698 7654 32 => [value removed] [iban removed][value removed] [value removed] ok
Open 13 call +33 6 12 34 56 78 => call +33 6 12 34 56 78
Open 23 Le patient a le cancer du sein. => Le patient a le [health removed] [health removed].
Open 28 Le patient a un cancer du colon. => Le patient a un [health removed] [health removed].
Open 29 Le patient a la maladie de Crohn => Le patient a la [health removed][value removed]
Open 33 Le patient a le diabète de type  => Le patient a le [health removed] [health removed].
Open 37 Send it to 10 Downing Street, Lo => Send it to [address removed][address removed] [address removed] today.
Open 25 Écrire au 12 rue de la Paix, 750 => Écrire au [address removed][value removed] [address removed].
Open 27 See https://example.com/private/ => See https://example.com/private/page now.
Open 25 See www.example.org/page?id=42&r => See www.example.org/page?id=42&ref=mail now.
Open 24 mail alice@example.com.fake.com  => mail alice@example.com.fake.com now.
Open 11 My key is sk-proj-Fake0123456789 => My key is [secret removed].
Open 19 Passport P<GBRDOE<JOHN<<<<<<<<<< => Passport [value removed][id removed]
Open 15 Company number 12345678 => Company number [id removed]
Open 11 Adószám: 12345678-2-42 => Adószám: [id removed]
Open 15 VAT reg no: GB 123 4567 89 => VAT reg no: [id removed]
Open 17 password: hunter2⏎Thanks a lot,  => password: [secret removed] [secret removed]
Open 18 password: hunter2 ⏎see you at no => password: [secret removed]  [secret removed]
Open 28 Send it to 10 Downing Street tod => Send it to [address removed] today at noon.
Open 27 Meeting With Jean Dupont At 10 D => Meeting With Jean Dupont At [address removed]
Open 25 Meet at 10 Downing Street Thanks => Meet at [address removed] Thanks Jean.
Open 26 Write to 12 rue de la Paix Lyon  => Write to [address removed] Lyon today.
Open 26 Write to 12 rue de la Paix Lille => Write to [address removed] Lille.
Open 21 Ship to 5 High Street Uber Orang => Ship to [address removed] [address removed]
Open 230 My key:⏎-----BEGIN PRIVATE KEY-- => My key: [secret removed] [secret removed] [secret removed]
Open 787 My key:⏎MIIEvQIBADANRkFLRSBLRVkg => My key: [secret removed] [secret removed] (That was all.)
Open 850 0123456789abcdef⏎0123456789abcde => [auxesis: withheld]
Open 855 ----⏎0123456789abcdef⏎0123456789 => [auxesis: withheld]
Open 1712 id,password⏎0123456789abcdef,fed => [auxesis: withheld]";

/// The words `joined` shows past those `main` shows, counted.
fn past(main: &str, joined: &str) -> Vec<String> {
    let mut left = clear_words(main);
    let words = clear_words(joined).into_iter();
    let shown = words.filter(|word| match left.iter().position(|kept| kept == word) {
        Some(at) => left.swap_remove(at).is_empty(),
        None => true,
    });
    shown.collect()
}

#[test]
fn a_join_hides_all_that_main_hid_and_all_the_whole_text_hides() {
    let main: HashMap<&str, &str> = MAIN_JOINS
        .lines()
        .filter_map(|line| line.split_once(" => "))
        .collect();
    let (mut seen, mut failures) = (Vec::new(), Vec::new());
    for (name, mut gate) in gates() {
        for parts in corpus() {
            let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
            let [whole, _, joined] = split(&mut gate, &parts);
            let case = case(name, &parts);
            // Where main withheld, the join need only hide what the whole text hides.
            let past = match main.get(case.as_str()) {
                Some(&WITHHELD) => Vec::new(),
                Some(main) => past(main, &joined),
                None => vec![format!("no main join for {case}")],
            };
            seen.push(case);
            let shown = shown_pieces(&parts.concat(), &whole, &joined);
            if !past.is_empty() || !shown.is_empty() {
                failures.push(format!(
                    "{name} {parts:?}\n  whole  {whole}\n  joined {joined}\n  past main {past:?}\n  shows  {shown:?}"
                ));
            }
        }
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), main.len(), "a main join per case");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A table's secret cells after a seam, far from its header, stay hidden.
#[test]
fn a_secret_column_cut_far_from_its_header_stays_hidden() {
    let rows = "0123456789abcdef,fedcba9876543210\n".repeat(50);
    let (head, tail) = (format!("id,password\n{rows}"), rows.clone());
    let text = format!("{head}{tail}");
    for (name, mut gate) in gates() {
        let [whole, _, joined] = split(&mut gate, &[&head, &tail]);
        assert!(!whole.contains("fedcba"), "{name} {whole}");
        let shown = shown_pieces(&text, &whole, &joined);
        assert!(shown.is_empty(), "{name} {joined} {shown:?}");
    }
}

/// A key body wrapped at 32 columns, under a label or a key's name, cut at a
/// line break: no line of it shows. Main withheld it once the body runs past
/// the widest window (80 lines); a shorter one it read whole, as the gate does.
#[test]
fn a_key_wrapped_at_32_columns_cut_at_a_line_break_stays_hidden() {
    let line = "U1RTIE9OTFkgRkFLRSBLRVkgRk9SIFRF";
    let body = [line; 80].join("\n");
    for text in [format!("My key:\n{body}\n"), format!("secret: {body}\n")] {
        let at = text.match_indices('\n').nth(40).expect("break").0 + 1;
        for (name, mut gate) in gates() {
            let [_, _, joined] = split(&mut gate, &[&text[..at], &text[at..]]);
            assert!(!joined.contains(line), "{name} {joined}");
        }
    }
}

/// A table cut right under its header: no cell is hidden before the seam, and
/// the rows after it stay hidden, whatever the delimiter.
#[test]
fn a_secret_table_cut_right_under_its_header_stays_hidden() {
    for delim in [",", ";", "\t", "|"] {
        let rows = format!("0123456789abcdef{delim}fedcba9876543210\n").repeat(50);
        let head = format!("id{delim}password\n");
        let text = format!("{head}{rows}");
        for (name, mut gate) in gates() {
            let [whole, _, joined] = split(&mut gate, &[&head, &rows]);
            assert!(!whole.contains("fedcba"), "{name} {delim:?} {whole}");
            let shown = shown_pieces(&text, &whole, &joined);
            assert!(shown.is_empty(), "{name} {delim:?} {joined} {shown:?}");
        }
    }
}

/// A padded table (`, ` cells) cut far below its header, past 16 KiB: the
/// rows after the seam stay hidden, as the cells hidden before it say.
#[test]
fn a_padded_secret_table_cut_far_below_its_header_stays_hidden() {
    for delim in [", ", " ; ", "\t", " | "] {
        let row = |n: usize| format!("{n}{delim}fedcba9876543210\n");
        let head = format!(
            "id{delim}password\n{}",
            (0..900).map(row).collect::<String>()
        );
        let tail: String = (900..1000).map(row).collect();
        let text = format!("{head}{tail}");
        for (name, mut gate) in gates() {
            let [whole, _, joined] = split(&mut gate, &[&head, &tail]);
            assert!(!whole.contains("fedcba"), "{name} {delim:?} whole");
            let shown = shown_pieces(&text, &whole, &joined);
            assert!(
                shown.is_empty(),
                "{name} {delim:?} shown={}",
                joined.matches("fedcba").count()
            );
        }
    }
}

/// A table of wide rows cut in a row's notes: its header and the last cell
/// hidden before the seam are both past 16 KiB back, and the rows after the
/// seam stay hidden.
#[test]
fn a_secret_table_of_wide_rows_cut_far_from_its_header_stays_hidden() {
    let notes = "lorem ipsum ".repeat(1500);
    let rows: String = (0..3)
        .map(|n| format!("{n},fedcba98765432{n:02},{notes}\n"))
        .collect();
    let text = format!("id,password,notes\n{rows}");
    let at = text.find("fedcba9876543201").expect("row") + 17 * 1024;
    let at = text[..at].rfind(' ').expect("blank") + 1;
    for (name, mut gate) in gates() {
        let [whole, _, joined] = split(&mut gate, &[&text[..at], &text[at..]]);
        assert!(!whole.contains("fedcba"), "{name} whole");
        let shown = joined.matches("fedcba").count();
        assert_eq!(shown, 0, "{name} joined shows {shown} cells");
    }
}

/// A block indented under its label past a blank line, cut at the blank line:
/// the whole text hides the block, so no line of it shows.
#[test]
fn a_block_under_a_label_and_a_blank_line_cut_at_the_blank_stays_hidden() {
    let line = "    U1RTIE9OTFkgRkFLRSBLRVkgRk9SIFRF";
    let text = format!("private_key:\n\n{}\n", [line; 20].join("\n"));
    let blank = text.find("\n\n").expect("blank line");
    for at in [blank + 1, blank + 2] {
        for (name, mut gate) in gates() {
            let [whole, _, joined] = split(&mut gate, &[&text[..at], &text[at..]]);
            assert!(!whole.contains(line.trim()), "{name} whole {whole}");
            assert!(!joined.contains(line.trim()), "{name} {at} {joined}");
        }
    }
}

/// A secret table whose header the seam cuts (`id,passw` + `ord`): no cell shows.
#[test]
fn a_secret_header_cut_by_the_seam_shows_no_cell() {
    let rows = "0123456789abcdef,fedcba9876543210\n".repeat(50);
    let text = format!("id,password\n{rows}");
    for at in ["id,".len(), "id,passw".len(), "id,password".len()] {
        for (name, mut gate) in gates() {
            let [whole, _, joined] = split(&mut gate, &[&text[..at], &text[at..]]);
            assert!(!whole.contains("fedcba"), "{name} whole");
            assert!(!joined.contains("fedcba"), "{name} {at} {joined}");
        }
    }
}

/// A word that only holds a key word (`monkey`, `tokenizer`) names no key, and
/// prose after a table that a line closed is out of it: both join as the whole.
#[test]
fn a_key_word_inside_a_word_or_prose_after_a_closed_table_joins() {
    let hex = "0123456789abcdef\n".repeat(60);
    let rows = "0123456789abcdef,fedcba9876543210\n".repeat(5);
    let prose = "Hello, see the notes below for more\n".repeat(40);
    let texts = [
        format!("monkey:\n{hex}"),
        format!("tokenizer:\n{hex}"),
        format!("id,password\n{rows}That was all.\n{prose}"),
    ];
    for text in texts {
        let at = text.len() * 2 / 3;
        let at = text[..at].rfind('\n').expect("break") + 1;
        for (name, mut gate) in gates() {
            let [whole, concat, joined] = split(&mut gate, &[&text[..at], &text[at..]]);
            assert_ne!(joined, WITHHELD, "{name} {}", &text[..12]);
            assert!(whole == concat && joined == concat, "{name} {}", &text[..12]);
        }
    }
}

/// A join stays linear: a megabyte of delimited lines, an e-mail on each, in
/// 1 KiB parts joins within the bound.
#[test]
fn a_megabyte_in_kibibyte_parts_joins_fast() {
    let line = "Room 12, budget; notes | write to ann@example.com today\n";
    let text = line.repeat(1024 * 1024 / line.len());
    for (name, mut gate) in gates() {
        let issued: Vec<SafeText> = text
            .as_bytes()
            .chunks(1024)
            .map(|part| gate.text(std::str::from_utf8(part).expect("ascii")).expect("issued").0)
            .collect();
        let started = std::time::Instant::now();
        let joined = SafeText::join(issued);
        let took = started.elapsed();
        assert_ne!(joined.as_str(), WITHHELD, "{name}");
        assert!(took.as_millis() < 1000, "{name} took {took:?}");
    }
}
