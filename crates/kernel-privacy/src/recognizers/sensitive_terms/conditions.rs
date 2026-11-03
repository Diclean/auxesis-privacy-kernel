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
            let leading_classifier = PERSONAL_CLASSIFIERS.contains(&prev.folded.as_str())
                && (personal_frames[frame_index] || terminal_condition(text, words, last));
            if !valid_extension_gap(
                text,
                prev.end,
                words[first].start,
                false,
                leading_classifier,
            ) || coordinator_needs_peer
                || (PERSONAL_CLASSIFIERS.contains(&prev.folded.as_str()) && !leading_classifier)
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
                break;
            }
            last += 1;
        }
        span.start = words[first].start;
        span.end = words[last].end;
    }
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
    for hit in hits
        .iter_mut()
        .filter(|hit| hit.span.kind == EntityKind::Health)
    {
        let Some(&index) = starts.get(&hit.span.start) else {
            continue;
        };
        let Some(&last) = ends.get(&hit.span.end) else {
            continue;
        };
        if !QUANTIFIED_TERMS.contains(&words[index].folded.as_str()) {
            continue;
        }
        if let Some(end) = quantity_end(text, words[last].end) {
            hit.span.end = end;
        }
    }
}

/// End of a directly attached numeric measurement with a recognised unit.
fn quantity_end(text: &str, from: usize) -> Option<usize> {
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
    ];
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
    // One linking word may stand before the value: "HbA1c is 8.1 %".
    const LINKS: &[&str] = &["is", "was", "at", "of", "est", "à", "de"];
    let link_end = text[at..]
        .char_indices()
        .take(4)
        .find(|(_, ch)| !ch.is_alphabetic())
        .map(|(offset, _)| at + offset);
    if let Some(link_end) = link_end.filter(|&end| {
        end > at
            && LINKS.contains(&text[at..end].to_lowercase().as_str())
            && text[end..].starts_with(char::is_whitespace)
    }) {
        at = link_end;
        while let Some(ch) = text[at..].chars().next().filter(|ch| ch.is_whitespace()) {
            at += ch.len_utf8();
            if at - link_end > 8 {
                return None;
            }
        }
    }
    let number_start = at;
    while at - number_start < 16 && text.as_bytes().get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    if at == number_start {
        return None;
    }
    if text.as_bytes().get(at).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    if text
        .as_bytes()
        .get(at)
        .is_some_and(|byte| matches!(byte, b'.' | b','))
        && text.as_bytes().get(at + 1).is_some_and(u8::is_ascii_digit)
    {
        at += 1;
        while at - number_start < 16 && text.as_bytes().get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if text.as_bytes().get(at).is_some_and(u8::is_ascii_digit) {
            return None;
        }
    }
    let unit_space_start = at;
    while text
        .get(at..)?
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
    {
        at += text[at..].chars().next()?.len_utf8();
        if at - unit_space_start > 8 {
            return None;
        }
    }
    for unit in UNITS {
        let Some(end) = at.checked_add(unit.len()) else {
            continue;
        };
        let Some(candidate) = text.get(at..end) else {
            continue;
        };
        if candidate.eq_ignore_ascii_case(unit)
            && !text
                .get(end..)?
                .chars()
                .next()
                .is_some_and(char::is_alphanumeric)
        {
            return Some(end);
        }
    }
    None
}
