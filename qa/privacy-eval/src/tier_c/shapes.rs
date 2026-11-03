//! Structural miss buckets for Tier C: counts only, never a value.

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::recognizers::sensitive_terms::SensitiveTermsRecognizer;
use kernel_privacy::{EntityKind, Recognizer, Span};

use crate::cases::Case;

use super::TierCPaths;

fn add_shape(
    paths: &mut TierCPaths,
    class: &'static str,
    mode: &'static str,
    feature: &'static str,
    bucket: &'static str,
) {
    *paths
        .miss_shape
        .entry((class, mode, feature, bucket))
        .or_default() += 1;
}

/// Structural characteristics only. The caller never stores the value or text.
pub(crate) fn miss_shape(
    paths: &mut TierCPaths,
    mode: &'static str,
    class: &'static str,
    case: &Case,
    gold: &GoldSpan,
    predicted: &[Span],
    issued: Option<&str>,
) {
    let value = case.text.get(gold.start..gold.end).unwrap_or("");
    let overlapping: Vec<&Span> = predicted
        .iter()
        .filter(|span| span.start < gold.end && gold.start < span.end)
        .collect();
    let failure = if issued.is_none() {
        "refusal"
    } else if overlapping.is_empty() {
        "no overlapping span"
    } else {
        let mut covered: Vec<(usize, usize)> = overlapping
            .iter()
            .map(|span| (span.start.max(gold.start), span.end.min(gold.end)))
            .collect();
        covered.sort_unstable();
        let bytes = covered
            .into_iter()
            .fold(Vec::<(usize, usize)>::new(), |mut acc, span| {
                if let Some(last) = acc.last_mut().filter(|last| span.0 <= last.1) {
                    last.1 = last.1.max(span.1);
                } else {
                    acc.push(span);
                }
                acc
            });
        let covered_len: usize = bytes.iter().map(|(start, end)| end - start).sum();
        if covered_len < value.len() {
            if covered_len > 0 {
                let before = bytes.first().is_some_and(|(start, _)| *start > gold.start);
                let after = bytes.last().is_some_and(|(_, end)| *end < gold.end);
                add_shape(
                    paths,
                    class,
                    mode,
                    "uncovered remainder",
                    match (before, after) {
                        (true, true) => "both sides",
                        (true, false) => "before",
                        (false, true) => "after",
                        (false, false) => "both sides",
                    },
                );
            }
            if covered_len * 2 < value.len() {
                "partial coverage <50%"
            } else {
                "partial coverage 50-99%"
            }
        } else if overlapping.iter().any(|span| !span.kind.is_prohibited()) {
            "fully covered, non-prohibited kind"
        } else {
            "fully covered, prohibited kind"
        }
    };
    add_shape(paths, class, mode, "failure mode", failure);

    let len = value.chars().count();
    add_shape(
        paths,
        class,
        mode,
        "value length",
        match len {
            1..=8 => "1-8 chars",
            9..=20 => "9-20 chars",
            21..=40 => "21-40 chars",
            _ => "41+ chars",
        },
    );
    let has_han = value.chars().any(is_han);
    let has_latin = value.chars().any(is_latin);
    add_shape(
        paths,
        class,
        mode,
        "script",
        if has_han {
            "Han"
        } else if has_latin {
            "Latin"
        } else {
            "other"
        },
    );
    add_shape(
        paths,
        class,
        mode,
        "label cue within 40 chars",
        if has_label_cue(&case.text, gold.start) {
            "yes"
        } else {
            "no"
        },
    );
    add_shape(
        paths,
        class,
        mode,
        "spans line break",
        if value.contains('\n') || value.contains('\r') {
            "yes"
        } else {
            "no"
        },
    );
    add_shape(
        paths,
        class,
        mode,
        "contains digits",
        if value.chars().any(|ch| ch.is_ascii_digit()) {
            "yes"
        } else {
            "no"
        },
    );
    if gold.kind == EntityKind::Health {
        add_shape(
            paths,
            class,
            mode,
            "health phrase",
            if value.split_whitespace().count() <= 1 {
                "single word"
            } else {
                "multi-word"
            },
        );
    }

    add_requested_miss_shapes(paths, class, mode, case, gold, value);
}

fn add_requested_miss_shapes(
    paths: &mut TierCPaths,
    class: &'static str,
    mode: &'static str,
    case: &Case,
    gold: &GoldSpan,
    value: &str,
) {
    let lexicon_hit = SensitiveTermsRecognizer::new()
        .analyze(value)
        .iter()
        .any(|span| span.kind == EntityKind::Health && span.start < value.len() && span.end > 0);
    add_shape(
        paths,
        class,
        mode,
        "any lexicon term",
        if lexicon_hit { "yes" } else { "no" },
    );

    let (sentence_start, sentence_end) = sentence_bounds(&case.text, gold.start, gold.end);
    let sentence = &case.text[sentence_start..sentence_end];
    add_shape(
        paths,
        class,
        mode,
        "personal frame",
        if has_personal_frame(sentence) {
            "yes"
        } else {
            "no"
        },
    );
    add_shape(paths, class, mode, "gold category", gold_category(value));
    let sentence_len = sentence.chars().count();
    add_shape(
        paths,
        class,
        mode,
        "sentence length",
        match sentence_len {
            0..=60 => "≤ 60 chars",
            61..=150 => "61–150 chars",
            _ => "> 150 chars",
        },
    );
    let chars_before = case.text[sentence_start..gold.start].chars().count();
    let chars_in = case.text[gold.start..gold.end].chars().count();
    let chars_after = sentence_len.saturating_sub(chars_before + chars_in);
    add_shape(
        paths,
        class,
        mode,
        "span position",
        if chars_before <= sentence_len / 3 {
            "start"
        } else if chars_after <= sentence_len / 3 {
            "end"
        } else {
            "middle"
        },
    );
}

fn sentence_bounds(text: &str, start: usize, end: usize) -> (usize, usize) {
    let before = &text[..start];
    let sentence_start = before
        .char_indices()
        .rev()
        .find(|(_, ch)| matches!(ch, '.' | '!' | '?' | '。' | '！' | '？' | '\n' | '\r'))
        .map_or(0, |(i, ch)| i + ch.len_utf8());
    let after = &text[end..];
    let sentence_end = after
        .char_indices()
        .find(|(_, ch)| matches!(ch, '.' | '!' | '?' | '。' | '！' | '？' | '\n' | '\r'))
        .map_or(text.len(), |(i, _)| end + i);
    (sentence_start, sentence_end)
}

fn has_personal_frame(sentence: &str) -> bool {
    const FRAMES: &[&str] = &[
        "i",
        "me",
        "my",
        "mine",
        "we",
        "us",
        "our",
        "ours",
        "you",
        "your",
        "yours",
        "he",
        "him",
        "his",
        "she",
        "her",
        "hers",
        "they",
        "them",
        "their",
        "theirs",
        "je",
        "me",
        "moi",
        "mon",
        "ma",
        "mes",
        "nous",
        "notre",
        "nos",
        "tu",
        "te",
        "toi",
        "ton",
        "ta",
        "tes",
        "vous",
        "votre",
        "vos",
        "il",
        "elle",
        "on",
        "ils",
        "elles",
        "leur",
        "leurs",
        "ek",
        "my",
        "ons",
        "onze",
        "jy",
        "jou",
        "julle",
        "hy",
        "sy",
        "hulle",
        "én",
        "engem",
        "enyém",
        "mi",
        "minket",
        "miénk",
        "te",
        "téged",
        "tiéd",
        "ő",
        "őt",
        "övé",
        "mi",
        "minket",
        "ők",
        "övék",
        "jaz",
        "me",
        "moj",
        "moja",
        "moje",
        "midva",
        "mi",
        "naš",
        "naša",
        "ti",
        "tebe",
        "tvoj",
        "tvoja",
        "on",
        "ona",
        "oni",
        "one",
        "njihov",
        "我",
        "我们",
        "我的",
        "我们的",
        "你",
        "你们",
        "你的",
        "你们的",
        "他",
        "她",
        "他们",
        "她们",
        "他的",
        "她的",
        "他们的",
    ];
    let folded = sentence.to_lowercase();
    folded
        .split(|ch: char| !ch.is_alphanumeric())
        .any(|word| FRAMES.contains(&word))
        || FRAMES
            .iter()
            .any(|frame| frame.chars().any(is_han) && folded.contains(frame))
}

fn gold_category(value: &str) -> &'static str {
    let s = value.to_lowercase();
    let has = |terms: &[&str]| terms.iter().any(|term| s.contains(term));
    if has(&[
        "mg",
        "mcg",
        "dose",
        "tablet",
        "pill",
        "medication",
        "medicine",
        "drug",
        "insulin",
        "metformin",
        "mg",
        "médicament",
        "dose",
        "dosis",
        "gyógyszer",
        "lek",
        "药",
        "药物",
    ]) {
        "medication/dose"
    } else if has(&[
        "surgery",
        "surgical",
        "procedure",
        "operation",
        "biopsy",
        "transplant",
        "chirurgie",
        "opération",
        "operacija",
        "műtét",
        "手术",
    ]) {
        "procedure/surgery"
    } else if has(&[
        "pain",
        "fever",
        "cough",
        "symptom",
        "nausea",
        "fatigue",
        "douleur",
        "fièvre",
        "toux",
        "symptôme",
        "tünet",
        "bolečina",
        "simptom",
        "症状",
    ]) {
        "symptom"
    } else if has(&[
        "diabetes",
        "cancer",
        "asthma",
        "disease",
        "diagnosis",
        "syndrome",
        "maladie",
        "diabète",
        "diagnostic",
        "betegség",
        "bolezen",
        "疾病",
        "糖尿病",
    ]) {
        "diagnosis/disease"
    } else if has(&[
        "depression",
        "anxiety",
        "bipolar",
        "schizophrenia",
        "mental",
        "dépression",
        "anxiété",
        "dušev",
        "精神",
        "抑郁",
    ]) {
        "mental health"
    } else if has(&[
        "disability",
        "disabled",
        "autism",
        "paralysis",
        "handicap",
        "invalid",
        "disability",
        "invalidit",
        "残疾",
    ]) {
        "disability"
    } else if has(&[
        "pregnan",
        "pregnancy",
        "menstru",
        "fertility",
        "reproductive",
        "enceinte",
        "grossesse",
        "terhess",
        "nosečnost",
        "怀孕",
    ]) {
        "pregnancy/reproductive"
    } else {
        "other"
    }
}

fn is_han(ch: char) -> bool {
    matches!(ch as u32, 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x20000..=0x2FA1F)
}

fn is_latin(ch: char) -> bool {
    matches!(ch as u32, 0x0041..=0x024F | 0x1E00..=0x1EFF)
}

fn has_label_cue(text: &str, value_start: usize) -> bool {
    const CUES: &[&str] = &[
        "diagnosis",
        "diagnostic",
        "diagnostique",
        "allergie",
        "allergy",
        "medication",
        "médicament",
        "medicament",
        "maladie",
        "condition",
        "treatment",
        "traitement",
        "santé",
        "sante",
        "health",
    ];
    let prefix = &text[..value_start.min(text.len())];
    let start = prefix
        .char_indices()
        .rev()
        .nth(39)
        .map_or(0, |(index, _)| index);
    let folded = prefix[start..].to_lowercase();
    CUES.iter().any(|cue| folded.contains(cue))
}
