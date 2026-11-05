//! Personal health conditions and quantified health values.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::span::{EntityKind, Span};

use super::lexicon::Hit;
use super::sentence::is_sentence_end;
use super::text::{fold_str, is_han, joins, words, HanView, Word};
use super::{NAME, SCORE};

/// Multiword conditions gated on a personal sentence frame.
const PERSONAL_CONDITIONS: &str = include_str!("../../../data/personal-health-conditions-v1.tsv");

/// Match multiword conditions only when a personal frame occurs in the same
/// sentence. The finite table keeps this scan linear in input length.
pub(super) fn personal_condition_spans(text: &str, word_list: &[Word]) -> Vec<Span> {
    static TERMS: OnceLock<HashMap<String, Vec<Vec<String>>>> = OnceLock::new();
    static HAN_TERMS: OnceLock<Vec<String>> = OnceLock::new();
    let terms = TERMS.get_or_init(|| {
        let mut indexed: HashMap<String, Vec<Vec<String>>> = HashMap::new();
        for term in PERSONAL_CONDITIONS
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .filter_map(|line| {
                let (lang, term) = line.split_once('\t')?;
                (lang != "zh").then_some(term)
            })
        {
            let tokens: Vec<String> = words(term).into_iter().map(|word| word.folded).collect();
            if let Some(first) = tokens.first() {
                indexed.entry(first.clone()).or_default().push(tokens);
            }
        }
        indexed
    });
    let han_terms = HAN_TERMS.get_or_init(|| {
        PERSONAL_CONDITIONS
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .filter_map(|line| {
                let (lang, term) = line.split_once('\t')?;
                (lang == "zh").then(|| HanView::new(term).text)
            })
            .collect()
    });
    let mut personal_frames: Option<Vec<bool>> = None;
    let mut out = Vec::new();
    for (start, word) in word_list.iter().enumerate() {
        let Some(candidates) = terms.get(&word.folded) else {
            continue;
        };
        let frames = personal_frames.get_or_insert_with(|| personal_frame_flags(text, word_list));
        for term in candidates {
            let end = start + term.len();
            if end > word_list.len()
                || word_list[start..end]
                    .iter()
                    .zip(term)
                    .any(|(word, token)| &word.folded != token)
                || (start + 1..end).any(|at| {
                    !joins_condition_phrase(text, word_list[at - 1].end, word_list[at].start)
                })
            {
                continue;
            }
            if frames[start] {
                out.push(Span::new(
                    EntityKind::Health,
                    word_list[start].start,
                    word_list[end - 1].end,
                    SCORE,
                    NAME,
                ));
            }
        }
    }
    if !han_terms.is_empty() && text.chars().any(is_han) {
        let view = HanView::new(text);
        let personal_frames = personal_frame_byte_flags(text);
        for term in han_terms {
            for (from, matched) in view.text.match_indices(term) {
                if let Some((start, end)) = view.original(from, from + matched.len()) {
                    if personal_frames[start] {
                        out.push(Span::new(EntityKind::Health, start, end, SCORE, NAME));
                    }
                }
            }
        }
    }
    out
}

/// A lexicon phrase may cross a line only at a visible hyphen continuation.
fn joins_condition_phrase(text: &str, from: usize, to: usize) -> bool {
    let Some(gap) = text.get(from..to) else {
        return false;
    };
    joins(text, from, to)
        && (!gap.contains(['\n', '\r'])
            || gap
                .trim_end_matches(['\n', '\r', ' '])
                .ends_with(['-', '‐', '‑', '–', '\\']))
}

/// Mark each Latin word in a sentence once, so a hit never rescans a sentence.
fn personal_frame_flags(text: &str, words: &[Word]) -> Vec<bool> {
    const FRAME: &[&str] = &[
        "i", "me", "my", "mine", "we", "our", "he", "his", "she", "her", "they", "their", "je",
        "j", "jaz", "ma", "mon", "mes", "moi", "elle", "il", "nous", "hy", "sy", "ek", "ons",
        "haar", "hul", "nekem", "nalam", "я", "мой", "моя", "мое",
    ];
    let mut flags = vec![false; words.len()];
    let mut first = 0;
    for boundary in 1..=words.len() {
        let ends_sentence = boundary == words.len()
            || text[words[boundary - 1].end..words[boundary].start]
                .chars()
                .any(|ch| is_sentence_end(ch) || ch == '\n' || ch == '\r');
        if !ends_sentence {
            continue;
        }
        let has_frame = words[first..boundary]
            .iter()
            .any(|word| FRAME.contains(&word.folded.as_str()));
        flags[first..boundary].fill(has_frame);
        first = boundary;
    }
    flags
}

/// Mark original byte positions in personally framed sentences, including Han text.
fn personal_frame_byte_flags(text: &str) -> Vec<bool> {
    const FRAME: &[&str] = &[
        "i", "me", "my", "mine", "we", "our", "he", "his", "she", "her", "they", "their", "je",
        "j", "jaz", "ma", "mon", "mes", "moi", "elle", "il", "nous", "hy", "sy", "ek", "ons",
        "haar", "hul", "nekem", "nalam", "я", "мой", "моя", "мое", "我", "我们", "我的",
    ];
    let mut flags = vec![false; text.len() + 1];
    let mut start = 0;
    for (at, ch) in text.char_indices() {
        if !is_sentence_end(ch) && ch != '\r' {
            continue;
        }
        let end = at + ch.len_utf8();
        let sentence = &text[start..end];
        let folded = fold_str(sentence);
        let sentence_words: HashSet<String> = words(sentence)
            .into_iter()
            .map(|word| word.folded)
            .collect();
        let framed = FRAME.iter().any(|frame| {
            if frame.chars().any(is_han) {
                folded.contains(frame)
            } else {
                sentence_words.contains(&fold_str(frame))
            }
        });
        flags[start..end].fill(framed);
        start = end;
    }
    if start < text.len() {
        let sentence = &text[start..];
        let folded = fold_str(sentence);
        let sentence_words: HashSet<String> = words(sentence)
            .into_iter()
            .map(|word| word.folded)
            .collect();
        let framed = FRAME.iter().any(|frame| {
            if frame.chars().any(is_han) {
                folded.contains(frame)
            } else {
                sentence_words.contains(&fold_str(frame))
            }
        });
        flags[start..=text.len()].fill(framed);
    }
    flags
}

/// Extend a health span through adjacent condition modifiers, bounded to six
/// tokens / sixty bytes and one physical line.
pub(super) fn extend_condition_spans(text: &str, words: &[Word], spans: &mut [Span]) {
    const MODIFIERS: &[&str] = &[
        "acute",
        "chronic",
        "mild",
        "moderate",
        "severe",
        "early",
        "onset",
        "late",
        "stage",
        "type",
        "left",
        "right",
        "bilateral",
        "unilateral",
        "post",
        "pre",
        "related",
        "gestational",
        "idiopathic",
        "juvenile",
        "focal",
        "viral",
        "infectious",
        "sided",
        "et",
        "en",
        "siekte",
        "tipe",
        "1",
        "2",
        "3",
        "4",
        "5",
        "i",
        "ii",
        "iii",
        // KV02-HEALTH: the same qualifiers in FR (after the condition), AF,
        // HU and SL (before it).
        "chronique",
        "chroniques",
        "aigu",
        "aigue",
        "leger",
        "legere",
        "modere",
        "moderee",
        "kroniese",
        "chroniese",
        "akute",
        "ernstige",
        "kronikus",
        "akut",
        "sulyos",
        "enyhe",
        "kronicna",
        "kronicni",
        "kronicno",
        "akutna",
        "akutni",
        "huda",
        "blaga",
    ];
    const CONDITION_WORDS: &[&str] = &[
        "multiple",
        "polycystic",
        "ovary",
        "ulcerative",
        "traumatic",
        "brain",
        "injury",
        "scoliosis",
        "colitis",
        "syndrome",
        "disorder",
        "disease",
        "arthritis",
        "fatigue",
        "migraine",
        "asthma",
        "diabetes",
        "depression",
        "anxiety",
        "kidney",
        "cancer",
        "sleep",
        "apnea",
        "lung",
        "pulmonary",
        "renal",
        "rheumatoid",
        "obstructive",
        "and",
        "et",
        "en",
    ];
    // Numeric disease classifications expand in personal prose. A terminal
    // leading classifier may also attach without a recognized frame, while a
    // trailing classifier must be complete and terminal.
    const PERSONAL_CLASSIFIERS: &[&str] =
        &["type", "stage", "1", "2", "3", "4", "5", "i", "ii", "iii"];
    let personal_frames = personal_frame_flags(text, words);
    let starts: HashMap<usize, usize> = words
        .iter()
        .enumerate()
        .map(|(index, word)| (word.start, index))
        .collect();
    let ends: HashMap<usize, usize> = words
        .iter()
        .enumerate()
        .map(|(index, word)| (word.end, index))
        .collect();
    for span in spans
        .iter_mut()
        .filter(|span| span.kind == EntityKind::Health)
    {
        let Some(&mut_first) = starts.get(&span.start) else {
            continue;
        };
        let Some(&mut_last) = ends.get(&span.end) else {
            continue;
        };
        let frame_index = mut_first;
        let condition_last = mut_last;
        let mut first = mut_first;
        let mut last = mut_last;
        while first > 0 && last - first + 2 <= 6 && span.end - words[first - 1].start <= 60 {
            let prev = &words[first - 1];
            let coordinator_needs_peer = matches!(prev.folded.as_str(), "and" | "et" | "en")
                && !(first > 1 && CONDITION_WORDS.contains(&words[first - 2].folded.as_str()));
            let classifier = PERSONAL_CLASSIFIERS.contains(&prev.folded.as_str());
            let framed = classifier
                && (personal_frames[frame_index] || terminal_condition(text, words, last));
            // KV02-HEALTH: a `type 2` or `stage III` pair right before a
            // condition in lower case is its classifier in any sentence.
            let leading_classifier =
                framed || (classifier && classifier_pair(text, words, first, mut_first));
            if !valid_extension_gap(text, prev.end, words[first].start, false, framed)
                || coordinator_needs_peer
                || (classifier && !leading_classifier)
                || (!MODIFIERS.contains(&prev.folded.as_str())
                    && !(personal_frames[frame_index]
                        && CONDITION_WORDS.contains(&prev.folded.as_str())))
            {
                break;
            }
            first -= 1;
        }
        while last + 1 < words.len()
            && last + 2 - first <= 6
            && words[last + 1].end - words[first].start <= 60
        {
            let next = &words[last + 1];
            let trailing_classifier =
                trailing_classifier_member(text, words, condition_last, last + 1);
            let coordinator_needs_peer = matches!(next.folded.as_str(), "and" | "et" | "en")
                && !(last + 2 < words.len()
                    && CONDITION_WORDS.contains(&words[last + 2].folded.as_str()));
            if !valid_extension_gap(
                text,
                words[last].end,
                next.start,
                trailing_classifier,
                false,
            ) || coordinator_needs_peer
                || (PERSONAL_CLASSIFIERS.contains(&next.folded.as_str())
                    && !personal_frames[frame_index]
                    && !trailing_classifier)
                || (!MODIFIERS.contains(&next.folded.as_str())
                    && !(personal_frames[frame_index]
                        && CONDITION_WORDS.contains(&next.folded.as_str()))
                    && !trailing_classifier)
            {
                // KV02-HEALTH: `type 2`, `de type 2`, `de stade 4`, `tipa 2`
                // right after the condition on its line, with no comma.
                match trailing_group(text, words, last) {
                    Some(end)
                        if end + 1 - first <= 6 && words[end].end - words[first].start <= 60 =>
                    {
                        last = end;
                        continue;
                    }
                    _ => break,
                }
            }
            last += 1;
        }
        // KV02-HEALTH: an allergy word takes its allergen, and a test verdict
        // right before a term is part of it.
        last = allergen_end(text, words, last).unwrap_or(last);
        first = verdict_start(text, words, first).unwrap_or(first);
        span.start = words[first].start;
        span.end = words[last].end;
    }
}

/// Whether the gap before word `at` joins it to the word before it on one
/// line, with no comma: the gap a link word takes.
fn linked(text: &str, words: &[Word], at: usize) -> bool {
    valid_extension_gap(text, words[at - 1].end, words[at].start, false, false)
}

/// The last word of the allergen after an allergy word `last`: `allergic to
/// penicillin`, `allergie aux arachides`, `allergique à la pénicilline`,
/// `allergies vir grondboontjies`, `alergijo na arašide`. One or two words of
/// letters, on the line, never a link word.
fn allergen_end(text: &str, words: &[Word], last: usize) -> Option<usize> {
    const LINKS: &[&str] = &["to", "a", "au", "aux", "vir", "teen", "na"];
    const ARTICLES: &[&str] = &["the", "la", "le", "l", "les", "die"];
    const STOP: &[&str] = &[
        "and", "or", "but", "so", "since", "because", "when", "which", "who", "that", "too",
        "also", "for", "from", "with", "after", "before", "et", "ou", "mais", "donc", "car",
        "depuis", "qui", "que", "pour", "avec", "en", "of", "maar", "want", "sedert", "ook", "in",
        "ali", "zato", "ker", "ki", "tudi", "za", "je", "is", "il", "elle",
    ];
    let is = |at: usize, list: &[&str]| {
        words
            .get(at)
            .is_some_and(|word| list.contains(&word.folded.as_str()))
    };
    let allergy = words[last].folded.as_str();
    if !(allergy.starts_with("allerg") || allergy.starts_with("alerg")) || !is(last + 1, LINKS) {
        return None;
    }
    let first = last + 2 + usize::from(is(last + 2, ARTICLES));
    let allergen = |at: usize| {
        words.get(at).is_some_and(|word| {
            word.folded.chars().count() >= 3
                && word.folded.chars().all(char::is_alphabetic)
                && !STOP.contains(&word.folded.as_str())
        }) && linked(text, words, at)
    };
    if !(last + 1..first).all(|at| linked(text, words, at)) || !allergen(first) {
        return None;
    }
    Some(first + usize::from(allergen(first + 1)))
}

/// The first word of a test verdict right before a term at word `first`:
/// `tested positive for COVID`, `testé positif au covid`.
fn verdict_start(text: &str, words: &[Word], first: usize) -> Option<usize> {
    const VERBS: &[&str] = &["tested", "tests", "test", "teste", "testee", "testes"];
    const VERDICTS: &[&str] = &["positive", "negative", "positif", "negatif"];
    let article = first > 0 && matches!(words[first - 1].folded.as_str(), "la" | "l");
    let start = (first - usize::from(article)).checked_sub(3)?;
    let is = |at: usize, list: &[&str]| list.contains(&words[at].folded.as_str());
    let found = is(start, VERBS)
        && is(start + 1, VERDICTS)
        && is(start + 2, &["for", "au", "a", "aux"])
        && (start + 1..=first).all(|at| linked(text, words, at));
    found.then_some(start)
}

/// The classifier numbers of a `type 2` or `stage III` group, folded.
const CLASSIFIER_NUMBERS: &[&str] = &["1", "2", "3", "4", "5", "i", "ii", "iii"];

/// Whether the classifier word before `first` is half of a `type 2` or `stage
/// III` pair that ends at `first`, before a condition (word `condition`) that
/// starts in lower case: `type 2 diabetes` is the condition in any sentence,
/// `Type 2 Diabetes Care` is a title. A capital `Type` keeps main's reading (the
/// eval line `Type 2 diabetes was found during the checkup.` masks the
/// condition only); a capital `Stage` opens a staged condition.
fn classifier_pair(text: &str, words: &[Word], first: usize, condition: usize) -> bool {
    const NAMES: &[&str] = &["type", "tipe", "stage"];
    let number = |word: &Word| CLASSIFIER_NUMBERS.contains(&word.folded.as_str());
    let lower = |word: &Word| {
        text[word.start..]
            .chars()
            .next()
            .is_some_and(char::is_lowercase)
    };
    let prev = &words[first - 1];
    let name = if number(prev) {
        first.checked_sub(2).map(|at| &words[at])
    } else {
        number(&words[first]).then_some(prev)
    };
    name.is_some_and(|name| {
        NAMES.contains(&name.folded.as_str()) && (lower(name) || name.folded == "stage")
    }) && lower(&words[condition])
}

/// The last word of a classifier group right after word `last`: a `de` or `of`
/// may lead it (`diabétique de type 2`, `cancer de stade 4`), then a classifier
/// name and its number, all on one line with no comma.
fn trailing_group(text: &str, words: &[Word], last: usize) -> Option<usize> {
    const NAMES: &[&str] = &[
        "type", "tipe", "tipa", "stage", "stade", "stadium", "stadij", "stadiju", "stadija",
    ];
    let lead = words
        .get(last + 1)
        .is_some_and(|word| matches!(word.folded.as_str(), "de" | "of"));
    let name = last + 1 + usize::from(lead);
    let number = name + 1;
    let found = words
        .get(name)
        .is_some_and(|word| NAMES.contains(&word.folded.as_str()))
        && words
            .get(number)
            .is_some_and(|word| CLASSIFIER_NUMBERS.contains(&word.folded.as_str()))
        && (last + 1..=number)
            .all(|at| valid_extension_gap(text, words[at - 1].end, words[at].start, false, false));
    found.then_some(number)
}

/// Gaps accepted while extending a condition: ordinary joins, one comma and
/// following spaces before a complete trailing classifier, or one line break
/// after a leading classifier. Sentence punctuation and blank lines never join.
fn valid_extension_gap(
    text: &str,
    from: usize,
    to: usize,
    comma_allowed: bool,
    newline_allowed: bool,
) -> bool {
    let Some(gap) = text.get(from..to) else {
        return false;
    };
    if gap.chars().any(|ch| matches!(ch, '.' | '!' | '?' | ';'))
        || gap.contains("\n\n")
        || gap.contains("\r\n\r\n")
    {
        return false;
    }
    if joins(text, from, to) {
        return !gap.contains(['\n', '\r']) || (newline_allowed && one_line_break(gap));
    }
    comma_allowed
        && gap.starts_with(',')
        && gap.len() > 1
        && gap[1..].chars().all(char::is_whitespace)
        && !gap.contains(['\n', '\r'])
}

fn one_line_break(gap: &str) -> bool {
    let mut chars = gap.chars().peekable();
    let mut breaks = 0;
    while let Some(ch) = chars.next() {
        match ch {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                breaks += 1;
            }
            '\n' => breaks += 1,
            ' ' | '\t' => {}
            _ => return false,
        }
        if breaks > 1 {
            return false;
        }
    }
    breaks == 1
}

fn classifier_word(word: &str) -> bool {
    matches!(
        word,
        "type" | "tipe" | "stage" | "stadium" | "1" | "2" | "3" | "4" | "5" | "i" | "ii" | "iii"
    )
}

fn terminal_condition(text: &str, words: &[Word], last: usize) -> bool {
    let end = words[last].end;
    let tail = &text[end..];
    if tail.len() > 60 {
        return false;
    }
    tail.trim_start_matches(char::is_whitespace)
        .chars()
        .next()
        .is_none_or(|ch| matches!(ch, '.' | '!' | '?' | ';' | ','))
        || (last + 1 < words.len()
            && matches!(
                words[last + 1].folded.as_str(),
                "and" | "or" | "et" | "ou" | "en" | "of"
            ))
}

fn trailing_classifier_member(
    text: &str,
    words: &[Word],
    condition_last: usize,
    member: usize,
) -> bool {
    if member <= condition_last || member >= words.len() {
        return false;
    }
    let start = if member > 0 && classifier_word(&words[member - 1].folded) {
        member - 1
    } else {
        member
    };
    if !matches!(
        words[start].folded.as_str(),
        "type" | "tipe" | "stage" | "stadium"
    ) {
        return false;
    }
    let number = start + 1;
    if number >= words.len()
        || !matches!(
            words[number].folded.as_str(),
            "1" | "2" | "3" | "4" | "5" | "i" | "ii" | "iii"
        )
    {
        return false;
    }
    if member != start && member != number {
        return false;
    }
    if member == number
        && !matches!(
            words[start].folded.as_str(),
            "type" | "tipe" | "stage" | "stadium"
        )
    {
        return false;
    }
    if start != condition_last + 1
        || !valid_extension_gap(
            text,
            words[condition_last].end,
            words[start].start,
            true,
            false,
        )
        || !joins(text, words[start].end, words[number].start)
    {
        return false;
    }
    let after = number + 1;
    terminal_condition(text, words, number)
        || (after < words.len()
            && matches!(
                words[after].folded.as_str(),
                "and" | "or" | "et" | "ou" | "en" | "of"
            ))
}

/// A medicine strength or test result next to a known health term is part of
/// the personal health value. Numbers and units never create spans alone.
pub(super) fn extend_quantified_health(text: &str, words: &[Word], hits: &mut [Hit]) {
    const QUANTIFIED_TERMS: &[&str] = &[
        "metformin",
        "insulin",
        "amoxicillin",
        "sertraline",
        "citalopram",
        "escitalopram",
        "paroxetine",
        "venlafaxine",
        "duloxetine",
        "mirtazapine",
        "levothyroxine",
        "prednisone",
        "prednisolone",
        "ibuprofen",
        "paracetamol",
        "acetaminophen",
        "omeprazole",
        "pantoprazole",
        "lisinopril",
        "amlodipine",
        "losartan",
        "metoprolol",
        "salbutamol",
        "albuterol",
        "warfarin",
        "apixaban",
        "clopidogrel",
        "gabapentin",
        "tramadol",
        "morphine",
        "codeine",
        "oxycodone",
        "methotrexate",
        "tamoxifen",
        "hba1c",
        "cholesterol",
        "glycemie",
        "viral",
        "charge",
        "virale",
    ];
    let starts: HashMap<usize, usize> = words
        .iter()
        .enumerate()
        .map(|(index, word)| (word.start, index))
        .collect();
    let ends: HashMap<usize, usize> = words
        .iter()
        .enumerate()
        .map(|(index, word)| (word.end, index))
        .collect();
    // KV02-HEALTH: the lab, dose and pregnancy words a value may follow. Any
    // word of the hit may start with one of these or the terms above, and a
    // medicine name (lang `xx`) always takes its dose.
    const QUANTIFIED_STEMS: &[&str] = &[
        "tsh",
        "psa",
        "haemoglobin",
        "hemoglobin",
        "glyquee",
        "glucose",
        "sugar",
        "pressure",
        "arterielle",
        "creatinin",
        "ferritin",
        "egfr",
        "triglycerid",
        "insulien",
        "inzulin",
        "vercuk",
        "koleszterin",
        "sladkor",
        "bloedsuiker",
        "bloeddruk",
        "tlak",
        "pregnant",
        "swanger",
        "enceinte",
        "terhes",
        "nosec",
    ];
    for hit in hits
        .iter_mut()
        .filter(|hit| hit.span.kind == EntityKind::Health)
    {
        if hit.lang == "zh" {
            if let Some(end) = han_quantity_end(text, hit.span) {
                hit.span.end = end;
            }
            continue;
        }
        let Some(&index) = starts.get(&hit.span.start) else {
            continue;
        };
        let Some(&last) = ends.get(&hit.span.end) else {
            continue;
        };
        let quantified = hit.lang == "xx"
            || words[index..=last].iter().any(|word| {
                QUANTIFIED_TERMS
                    .iter()
                    .chain(QUANTIFIED_STEMS)
                    .any(|stem| word.folded.starts_with(stem))
            });
        if !quantified {
            continue;
        }
        if let Some(end) = quantity_end(text, words[last].end) {
            hit.span.end = end;
        }
        if let Some(start) = quantity_start(text, hit.span.start) {
            hit.span.start = start;
        }
    }
}

/// The units a measurement ends with. The longest one that matches wins.
const UNITS: &[&str] = &[
    "mg/dl",
    "mmol/l",
    "g/l",
    "copies/ml",
    "mcg",
    "µg",
    "μg",
    "units",
    "copies",
    "mg",
    "ml",
    "iu",
    "g",
    "%",
    // KV02-HEALTH: lab units, unit words in FR, AF, HU and SL, and the weeks
    // and months of a pregnancy.
    "mmol/mol",
    "µmol/l",
    "μmol/l",
    "umol/l",
    "nmol/l",
    "pmol/l",
    "mg/l",
    "ng/ml",
    "pg/ml",
    "µg/l",
    "μg/l",
    "miu/l",
    "mui/l",
    "mu/l",
    "iu/l",
    "ui/l",
    "u/l",
    "g/dl",
    "mmhg",
    "ml/min",
    "ui",
    "eenhede",
    "egység",
    "egységet",
    "enot",
    "mikrogramov",
    "tablets",
    "comprimés",
    "weeks",
    "months",
    "semaines",
    "mois",
    "weke",
    "maande",
];

/// End of a number at `start`: digits with one decimal part, or a reading
/// (`160/100`), which is `true`.
fn number_end(text: &str, start: usize) -> Option<(usize, bool)> {
    let bytes = text.as_bytes();
    let digits = |from: usize| {
        let mut at = from;
        while at - start < 16 && bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        (at > from && !bytes.get(at).is_some_and(u8::is_ascii_digit)).then_some(at)
    };
    let mut at = digits(start)?;
    if bytes
        .get(at)
        .is_some_and(|byte| matches!(byte, b'.' | b','))
        && bytes.get(at + 1).is_some_and(u8::is_ascii_digit)
    {
        at = digits(at + 1)?;
    }
    if bytes.get(at) == Some(&b'/') && bytes.get(at + 1).is_some_and(u8::is_ascii_digit) {
        // A reading, unless a date goes on after it (`12/03/2026`).
        if let Some(end) = digits(at + 1) {
            let date = matches!(bytes.get(end), Some(b'/' | b'.' | b'-'))
                && bytes.get(end + 1).is_some_and(u8::is_ascii_digit);
            if !date {
                return Some((end, true));
            }
        }
    }
    Some((at, false))
}

/// End of the longest unit after at most eight bytes of whitespace at `at`,
/// when no letter or digit is glued to it.
fn unit_end(text: &str, mut at: usize) -> Option<usize> {
    let space_start = at;
    while let Some(ch) = text
        .get(at..)?
        .chars()
        .next()
        .filter(|ch| ch.is_whitespace())
    {
        at += ch.len_utf8();
        if at - space_start > 8 {
            return None;
        }
    }
    UNITS
        .iter()
        .filter_map(|unit| {
            let end = at.checked_add(unit.len())?;
            let glued = text
                .get(end..)?
                .chars()
                .next()
                .is_some_and(char::is_alphanumeric);
            (text.get(at..end)?.eq_ignore_ascii_case(unit) && !glued).then_some(end)
        })
        .max()
}

/// Start of a measurement right before a term at `start`, on its line: `500
/// mg of metformin`, `500 mg d'amoxicilline`, `14 weeks pregnant`.
fn quantity_start(text: &str, start: usize) -> Option<usize> {
    let spaces = |head: &str| head.trim_end_matches([' ', '\u{a0}']).len();
    let word_end = |head: &str, word: &str| {
        let cut = head.len().checked_sub(word.len())?;
        let before = head.get(..cut)?.chars().next_back();
        (head.get(cut..)?.eq_ignore_ascii_case(word) && !before.is_some_and(char::is_alphabetic))
            .then_some(cut)
    };
    let mut at = spaces(&text[..start]);
    for link in ["of", "de", "van", "d'", "d\u{2019}"] {
        if let Some(cut) = word_end(&text[..at], link) {
            at = spaces(&text[..cut]);
            break;
        }
    }
    at = UNITS
        .iter()
        .filter_map(|unit| word_end(&text[..at], unit))
        .min()?;
    at = spaces(&text[..at]);
    let number =
        text[..at].trim_end_matches(|ch: char| ch.is_ascii_digit() || matches!(ch, '.' | ','));
    let from = number.len() + text[number.len()..at].find(|ch: char| ch.is_ascii_digit())?;
    let glued = number
        .chars()
        .next_back()
        .is_some_and(char::is_alphanumeric);
    (at - from <= 16 && text[..at].ends_with(|ch: char| ch.is_ascii_digit()) && !glued)
        .then_some(from)
}

/// End of a measurement right after a Han term: `二甲双胍500毫克`, `怀孕20周`,
/// `血压是160/100`. A bare number ends it only after a lab term (`血糖是11.2`).
fn han_quantity_end(text: &str, span: Span) -> Option<usize> {
    const HAN_UNITS: &[&str] = &[
        "毫克", "毫升", "微克", "单位", "克", "片", "粒", "周", "个月", "％",
    ];
    const LABS: &[&str] = &["血糖", "血压", "糖化血红蛋白", "胆固醇"];
    let mut at = span.end;
    if let Some(ch) = text[at..]
        .chars()
        .next()
        .filter(|ch| matches!(ch, '是' | '为' | '：' | ':' | '约'))
    {
        at += ch.len_utf8();
    }
    let (end, reading) = number_end(text, at)?;
    if let Some(unit) = HAN_UNITS.iter().find(|unit| text[end..].starts_with(*unit)) {
        return Some(end + unit.len());
    }
    if let Some(unit) = unit_end(text, end) {
        return Some(unit);
    }
    let lab = LABS.contains(&HanView::new(&text[span.start..span.end]).text.as_str());
    (reading || lab).then_some(end)
}

/// End of a directly attached numeric measurement with a recognised unit, or
/// of a reading (`160/100`).
fn quantity_end(text: &str, from: usize) -> Option<usize> {
    let mut at = from;
    while let Some(ch) = text.get(at..)?.chars().next() {
        if ch.is_whitespace() || matches!(ch, ',' | ':' | '-' | '‐' | '‑' | '–') {
            at += ch.len_utf8();
            if at - from > 8 {
                return None;
            }
        } else {
            break;
        }
    }
    // Linking words may stand before the value: "HbA1c is 8.1 %", and two
    // of them in "glycémie est à 1,32 g/l".
    const LINKS: &[&str] = &["is", "was", "at", "of", "est", "à", "de", "je", "van"];
    for _ in 0..2 {
        let link_end = text[at..]
            .char_indices()
            .take(4)
            .find(|(_, ch)| !ch.is_alphabetic())
            .map(|(offset, _)| at + offset);
        let Some(link_end) = link_end.filter(|&end| {
            end > at
                && LINKS.contains(&text[at..end].to_lowercase().as_str())
                && text[end..].starts_with(char::is_whitespace)
        }) else {
            break;
        };
        at = link_end;
        while let Some(ch) = text[at..].chars().next().filter(|ch| ch.is_whitespace()) {
            at += ch.len_utf8();
            if at - link_end > 8 {
                return None;
            }
        }
    }
    let (end, reading) = number_end(text, at)?;
    unit_end(text, end).or(reading.then_some(end))
}
