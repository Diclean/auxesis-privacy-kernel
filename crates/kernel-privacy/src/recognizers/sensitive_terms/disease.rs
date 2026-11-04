//! Invented disease names, Hungarian `rák` and cue frames.

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

use crate::contacts::fold::is_default_ignorable;
use crate::span::{EntityKind, Span};

use super::inflect::{hungarian_ending, hungarian_inflected, plain_match};
use super::lexicon::Hit;
use super::sentence::{char_floor, is_sentence_end};
use super::text::{fold_str, joins, Word};
use super::{NAME, SCORE};

/// Hungarian heads that follow a `rák` in a compound: rákszűrés, rákkutatás.
const HU_RAK_HEADS: &[&str] = &[
    "szűrés",
    "szűrő",
    "kutatás",
    "kutató",
    "kezel",
    "sejt",
    "megbetegedés",
    "betegség",
    "beteg",
    "ellenes",
    "gyógyszer",
    "műtét",
    "operáció",
    "diagnózis",
    "diagnosztika",
    "kockázat",
    "prevenció",
    "túlél",
    "halál",
    "elhalálozás",
    "statisztika",
    "központ",
    "intézet",
    "klinika",
    "orvos",
    "ellátás",
    "terápia",
    "szövet",
    "kórház",
    "tünet",
    "vizsgálat",
    "sugár",
    "kemoterápia",
];

/// Whether a raw, lower-cased, NFC word is Hungarian `rák` (cancer), with the
/// accent. A `rák` that starts the word is followed by a health head or a case
/// ending (rákszűrés, rákból). A `rák` that ends a compound has a root of three
/// letters or more (méhnyakrák, vastagbélrák). Bare `rak` and `árak` never match,
/// and neither does a place name (Rákospalota, Rákóczi).
fn hu_rak_word(word: &str) -> bool {
    if let Some(rest) = word.strip_prefix("rák") {
        return HU_RAK_HEADS.iter().any(|head| rest.starts_with(head))
            || hungarian_ending(&fold_str(rest));
    }
    match word.find("rák") {
        Some(index) => {
            let root = &word[..index];
            let ending = &word[index + "rák".len()..];
            root.chars().count() >= 3
                && root.chars().all(char::is_alphabetic)
                && hungarian_ending(&fold_str(ending))
        }
        None => false,
    }
}

/// Push the Hungarian `rák` words, matched on the raw word so the accent counts.
pub(super) fn push_hu_rak(text: &str, words: &[Word], out: &mut Vec<Hit>) {
    for word in words {
        let raw: String = text[word.start..word.end].to_lowercase().nfc().collect();
        // Rákos-patak is a stream: the word before `-patak` is a place, not a case.
        let place = text[word.end..].starts_with("-patak");
        if raw.contains("rák") && !place && hu_rak_word(&raw) {
            out.push(Hit {
                span: Span::new(EntityKind::Health, word.start, word.end, SCORE, NAME),
                contextual: false,
                lang: "hu",
            });
        }
    }
}

/// Disease words that make the capitalised word before them the name of a
/// disease: `Mist Fever`, `Köd-láz`, `Grys-koors`. Folded; `true` when the name
/// must be joined by a hyphen (Hungarian, Afrikaans), `contextual` when a health
/// anchor must share the sentence: a disease word carries the sentence on its
/// own, only a fever word asks for one (`Gold Fever` is a crowd, not a patient).
const DISEASE_HEADS: &[(&str, &[&str], bool, bool)] = &[
    ("en", &["fever"], false, true),
    ("en", &["disease", "syndrome"], false, false),
    // `Hashimoto thyroiditis`, `Bell's palsy`, `Hodgkin lymphoma`.
    (
        "en",
        &["palsy", "lymphoma", "thyroiditis", "chorea", "sarcoma"],
        false,
        false,
    ),
    ("hu", &["laz"], true, true),
    ("hu", &["betegseg", "szindroma", "kor"], true, false),
    ("af", &["griep", "koors"], true, true),
    ("af", &["siekte", "sindroom"], true, false),
];

/// A health hit on `from..to`.
pub(super) fn health(from: usize, to: usize, contextual: bool, lang: &'static str) -> Hit {
    let span = Span::new(EntityKind::Health, from, to, SCORE, NAME);
    Hit {
        span,
        contextual,
        lang,
    }
}

/// French disease words that a `de` and a capitalised name follow: `maladie de
/// Brume`, `syndrome d'Ombrelune`. Folded, with the same anchor rule as
/// [`DISEASE_HEADS`]: `fièvre de` asks for a health anchor, the two disease
/// words do not.
const DISEASE_LEADS: &[(&str, bool)] = &[
    ("maladie", false),
    ("syndrome", false),
    ("fievre", true),
    // `thyroïdite de Hashimoto`, `lymphome de Hodgkin`.
    ("thyroidite", false),
    ("lymphome", false),
    ("choree", false),
    ("sarcome", false),
];

/// Folded words that are never a disease name: articles, determiners and
/// pronouns that start a sentence (`This disease`, `No fever`).
const NOT_A_NAME: &[&str] = &[
    "the", "a", "an", "this", "that", "these", "those", "my", "his", "her", "our", "their", "your",
    "its", "no", "any", "some", "which", "what", "every", "each", "one", "such", "same", "az",
    "egy", "die", "n", "hierdie", "daardie", "le", "la", "les", "l", "un", "une", "du", "des",
    "de", "ce", "cette",
];

/// Folded honorifics: the word after one is a person (`Dr Brume`), never a disease.
pub(super) const HONORIFICS: &[&str] = &[
    "dr", "mr", "mrs", "ms", "miss", "prof", "mme", "mlle", "m", "me", "pr", "mev", "mnr", "dkt",
];

/// Folded words that name a figurative syndrome, never a patient's condition:
/// `Imposter syndrome` is a self-doubt habit, `Stockholm syndrome` a novel
/// cliché, `China syndrome` a building's nickname. They sit where the rules
/// above expect the name of a disease — the capitalised word before
/// `syndrome`, or after a French `de` — and nothing else in the sentence says
/// otherwise. `tall poppy` and `shiny object` need no entry: the word before
/// their `syndrome` is lower-case and never a name.
///
/// The list is idiom words only, and the guard that reads it is scoped to the
/// one shape the idiom takes (see [`figurative_syndrome`]): a real disease
/// whose name is also a place or a person must never land here. `Down`,
/// `Tourette`, `Asperger`, `Sjögren`, `Cushing` and `Guillain-Barré` all stay
/// masked, and so does every invented name this pass is for (`Mist Fever`,
/// `Grootrivier-sindroom`, `Grey-China syndrome`).
const FIGURATIVE_SYNDROMES: &[&str] = &["imposter", "impostor", "stockholm", "china", "poppy"];

/// Whether the name a disease word would mint is one of the idioms in `idioms`,
/// and so is not a patient's condition. The head decides, because only the head
/// tells an idiom from a disease: `Stockholm syndrome` is a cliché, while
/// `Stockholm-szindróma`, `Stockholm fever`, `Stockholm-sindroom` and
/// `Stockholm-koors` are names like any other. So is the same word before any
/// disease head but `syndrome` (`China Fever`, `Poppy disease`).
///
/// The name must also be the one word the rule resolved: a hyphen joins a
/// longer name (`Grey-China syndrome`, `Grey-Wing Syndrome`), and that name is
/// a disease like every other invented one.
fn figurative_syndrome(
    head: &str,
    idioms: &[&str],
    words: &[Word],
    first: usize,
    last: usize,
) -> bool {
    head == "syndrome" && first == last && idioms.contains(&words[last].folded.as_str())
}

/// The French `de` form carries one idiom only. `Le syndrome de Stockholm` is
/// a cliché of the novel, and the other four are diseases until a name says
/// otherwise: #202 masks `syndrome de Chine` and `syndrome d'Imposter` on
/// purpose (CHANGES ad205414), and this guard must not take that back.
const FRENCH_FIGURATIVE_SYNDROMES: &[&str] = &["stockholm"];

/// How far back a cue frame is looked for before a fever name, in bytes: a
/// constant, so the frame check keeps the scan linear.
const FRAME_WINDOW: usize = 64;

/// Folded line labels that make the fever name right after their colon the
/// record's health value: `Condition: Mist Fever`, `Toestand: As-koors`,
/// `Igazolás: Köd-láz`. #202 took these words off the sentence-wide cue list,
/// where they anchored idioms (`Market conditions: Crypto Fever`); as the
/// whole label of their own line they anchor only the name they introduce.
const FRAME_LABELS: &[&str] = &[
    "condition",
    "medical condition",
    "certificate",
    "medical certificate",
    "certificat",
    "certificat medical",
    "igazolas",
    "orvosi igazolas",
    "toestand",
    "mediese toestand",
];

/// Folded `certificate for` frames: the name after them, or after one
/// determiner, is what the certificate is for.
const FRAME_FOR: &[(&str, &str)] = &[("certificate", "for"), ("certificat", "pour")];

/// Folded determiners a `certificate for` frame may cross.
const FRAME_DETERMINERS: &[&str] = &[
    "a", "an", "the", "his", "her", "their", "my", "your", "our", "la", "le", "l", "sa", "son",
];

/// Folded words that make a certificate no health paper: `gift certificate`,
/// `SSL certificate`.
const FRAME_NOT_HEALTH: &[&str] = &["gift", "ssl", "tls"];

/// Start of the line label and colon before `start`, when the whole label is
/// in [`FRAME_LABELS`] (a list bullet aside).
fn labelled(text: &str, start: usize) -> Option<usize> {
    let from = char_floor(text, start.saturating_sub(FRAME_WINDOW));
    let window = text[from..start].trim_end_matches(char::is_whitespace);
    let (window, bold_colon) = window
        .strip_suffix("**")
        .map_or((window, false), |w| (w, true));
    let head = window.strip_suffix([':', '\u{ff1a}', '-'])?.trim_end();
    let line = head
        .char_indices()
        .rev()
        .find(|(_, ch)| is_sentence_end(*ch))
        .map(|(at, ch)| &head[at + ch.len_utf8()..])
        .or((from == 0).then_some(head));
    let label = line?.trim().trim_start_matches(['-', '\u{2022}']).trim();
    let label = label.strip_prefix("* ").unwrap_or(label).trim();
    let start = from + head.len() - label.len();
    let label = if let Some(bold) = label.strip_prefix("**") {
        if bold_colon {
            bold
        } else {
            bold.strip_suffix("**")?
        }
    } else if bold_colon {
        return None;
    } else {
        label
    };
    FRAME_LABELS
        .contains(&fold_str(label.trim()).as_str())
        .then_some(start)
}

/// Start of `certificate for` before the name at `first`, optionally crossing
/// one determiner (`certificate for his Mist Fever`).
fn certificate_for(text: &str, words: &[Word], first: usize) -> Option<usize> {
    let mut at = first;
    if at > 0
        && FRAME_DETERMINERS.contains(&words[at - 1].folded.as_str())
        && joins(text, words[at - 1].end, words[at].start)
    {
        at -= 1;
    }
    if at < 2 {
        return None;
    }
    let (cert, prep) = (&words[at - 2], &words[at - 1]);
    let matched = FRAME_FOR
        .iter()
        .any(|(c, p)| plain_match(&cert.folded, c) && prep.folded == *p)
        && joins(text, cert.end, prep.start)
        && joins(text, prep.end, words[at].start)
        && !(at > 2 && FRAME_NOT_HEALTH.contains(&words[at - 3].folded.as_str()));
    matched.then_some(cert.start)
}

/// Start of the Hungarian certificate the name on `first..=last` is for:
/// `igazolást kér a Köd-láz miatt`, the `igazolás` at most three
/// words before the name in the same sentence, `miatt` right after it.
fn igazolas_miatt(text: &str, words: &[Word], first: usize, last: usize) -> Option<usize> {
    if !words.get(last + 1).is_some_and(|w| w.folded == "miatt") {
        return None;
    }
    words[first.saturating_sub(3)..first]
        .iter()
        .find(|w| {
            w.folded.starts_with("igazolas")
                && !text[w.end..words[first].start].contains(is_sentence_end)
        })
        .map(|w| w.start)
}

/// Start of a cue #202 dropped that frames the disease name itself. The
/// caller collects frames separately, retaining only independent name anchors.
fn framed(text: &str, words: &[Word], first: usize, last: usize) -> Option<usize> {
    labelled(text, words[first].start)
        .or_else(|| certificate_for(text, words, first))
        .or_else(|| igazolas_miatt(text, words, first, last))
}

/// The Afrikaans disease heads that a `se` joins to the name before it, both
/// hyphenated and space-joined: `Down se sindroom`, `Addison se siekte`.
const AF_SE_HEADS: &[&str] = &["siekte", "sindroom"];

/// The most hyphen-joined words in a disease name (`Grey-Wing`).
const MAX_NAME_WORDS: usize = 3;

/// A name candidate: letters, at least two characters, no determiner. Case
/// heuristics apply unless this pass emits only validated cue frames.
pub(super) fn name_like(text: &str, word: &Word, frame_only: bool) -> bool {
    let raw = &text[word.start..word.end];
    (frame_only || raw.chars().next().is_some_and(char::is_uppercase))
        && raw.chars().count() >= 2
        && raw
            .chars()
            .all(|ch| ch.is_alphabetic() || is_default_ignorable(ch) || is_combining_mark(ch))
        && (frame_only || raw.chars().any(char::is_lowercase))
        && !NOT_A_NAME.contains(&word.folded.as_str())
}

/// Whether the text between two words is a single hyphen.
fn hyphen(text: &str, from: usize, to: usize) -> bool {
    matches!(&text[from..to], "-" | "\u{2010}" | "\u{2011}")
}

/// The first word of the disease name that ends at word `last`: hyphen-joined
/// name-like words, at most [`MAX_NAME_WORDS`], none after an honorific.
fn name_start(text: &str, words: &[Word], last: usize, frame_only: bool) -> Option<usize> {
    if !name_like(text, &words[last], frame_only) {
        return None;
    }
    let mut first = last;
    while first > 0
        && last - first + 1 < MAX_NAME_WORDS
        && hyphen(text, words[first - 1].end, words[first].start)
        && name_like(text, &words[first - 1], frame_only)
    {
        first -= 1;
    }
    let titled = first > 0 && {
        let before = &words[first - 1];
        let gap = &text[before.end..words[first].start];
        (joins(text, before.end, words[first].start) || gap.starts_with('.'))
            && HONORIFICS.contains(&before.folded.as_str())
    };
    (!titled).then_some(first)
}

/// Push the invented or rare disease names a disease word reveals: a name before
/// `fever`, `disease`, `-láz` or `-koors` (with an English possessive `'s` and
/// the Afrikaans `se`), and a name after the French `maladie de`. The span covers
/// name and disease word. A fever word needs a health term or cue in its
/// sentence; a disease word stands on its own.
pub(super) fn push_disease_names(text: &str, words: &[Word], out: &mut Vec<Hit>, frame_only: bool) {
    for (index, word) in words.iter().enumerate() {
        let head = DISEASE_HEADS
            .iter()
            .find_map(|(lang, cues, hyphenated, contextual)| {
                let cue = cues.iter().copied().find(|cue| match *lang {
                    // `kór` (disease) keeps its accent: `Árpád-kor` is an era.
                    "hu" if *cue == "kor" => {
                        hungarian_inflected(&word.folded, cue)
                            && text[word.start..word.end].to_lowercase().starts_with("kór")
                    }
                    "hu" => hungarian_inflected(&word.folded, cue),
                    _ => plain_match(&word.folded, cue),
                })?;
                Some((*lang, *hyphenated, *contextual, cue))
            });
        if let Some((lang, hyphenated, contextual, cue)) = head {
            let mut last = index.checked_sub(1);
            if let Some(at) = last {
                // `Down se sindroom`, `Addison se siekte`: the af disease heads
                // take the name through a `se`, and are space-joined to it,
                // while the other heads are hyphen-joined.
                let af_se = lang == "af"
                    && AF_SE_HEADS.iter().any(|cue| plain_match(&word.folded, cue))
                    && words[at].folded == "se";
                let joined = if hyphenated && !af_se {
                    hyphen(text, words[at].end, word.start)
                } else {
                    joins(text, words[at].end, word.start)
                };
                last = joined.then_some(at);
            }
            // `Brume's disease`: the `s` is the possessive of the name before it.
            if let Some(at) = last.filter(|&at| at > 0 && lang == "en" && words[at].folded == "s") {
                let between = &text[words[at - 1].end..words[at].start];
                last = matches!(between, "'" | "\u{2019}").then_some(at - 1);
            }
            // `Down se sindroom`: the `se` joins the name to the word.
            if let Some(at) = last.filter(|&at| at > 0 && lang == "af" && words[at].folded == "se")
            {
                last = joins(text, words[at - 1].end, words[at].start).then_some(at - 1);
            }
            if let Some(at) = last {
                if let Some(first) = name_start(text, words, at, frame_only) {
                    // `Stockholm syndrome` is a cliché, `Stockholm-szindróma`
                    // a patient: the head, not the word, decides.
                    if !figurative_syndrome(cue, FIGURATIVE_SYNDROMES, words, first, at) {
                        if frame_only {
                            if let Some(start) = framed(text, words, first, index) {
                                out.push(health(start, word.end, false, lang));
                            }
                        } else {
                            out.push(health(words[first].start, word.end, contextual, lang));
                        }
                    }
                }
            }
        }
        let lead = DISEASE_LEADS
            .iter()
            .find(|(lead, _)| plain_match(&word.folded, lead));
        if let Some(&(head, contextual)) = lead {
            if index > 0 && words[index - 1].folded == "assurance" {
                continue;
            }
            let (Some(de), Some(name)) = (words.get(index + 1), words.get(index + 2)) else {
                continue;
            };
            if !matches!(de.folded.as_str(), "de" | "d" | "du")
                || !joins(text, word.end, de.start)
                || !joins(text, de.end, name.start)
                || !name_like(text, name, frame_only)
                || HONORIFICS.contains(&name.folded.as_str())
            {
                continue;
            }
            let mut last = index + 2;
            while last + 1 < words.len()
                && last - index < 1 + MAX_NAME_WORDS
                && hyphen(text, words[last].end, words[last + 1].start)
                && name_like(text, &words[last + 1], frame_only)
            {
                last += 1;
            }
            if !figurative_syndrome(head, FRENCH_FIGURATIVE_SYNDROMES, words, index + 2, last) {
                if frame_only {
                    if let Some(start) = framed(text, words, index, last) {
                        out.push(health(start, words[last].end, false, "fr"));
                    }
                } else {
                    out.push(health(word.start, words[last].end, contextual, "fr"));
                }
            }
        }
    }
}
