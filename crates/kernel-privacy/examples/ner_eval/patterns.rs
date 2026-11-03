//! Why a person was missed: the messy pattern that hid it, and the public
//! terms the union over-masked.

use kernel_privacy::decode::url_ranges;
use kernel_privacy::eval::GoldSpan;
use kernel_privacy::span::EntityKind;
use kernel_privacy::PublicTerms;

use super::corpus::Case;

/// Greeting, closing and reply markers used to classify a missed person.
const GREETING_MARKERS: &[&str] = &[
    "bonjour",
    "salut",
    "coucou",
    "hello",
    "hi",
    "hey",
    "dear",
    "hallo",
    "beste",
    "liewe",
    "kedves",
    "szia",
    "привет",
    "مرحبا",
    "سلام",
];
const CLOSING_MARKERS: &[&str] = &[
    "cordialement",
    "bien à vous",
    "kind regards",
    "best regards",
    "thanks",
    "groete",
    "dankie",
    "üdvözlettel",
    "с уважением",
    "مع التحية",
    "شكرا",
];
const REPLY_MARKERS: &[&str] = &["wrote:", "a écrit", "geskryf", "írta", "написал", "كتب"];

/// Classify a gold person span by the messy pattern that hid it.
pub(crate) fn person_patterns(case: &Case, span: &GoldSpan) -> Vec<&'static str> {
    let text = &case.text;
    let value = &text[span.start..span.end];
    let mut patterns = Vec::new();
    if value.chars().count() <= 3 {
        patterns.push("short");
    }
    if !value.chars().any(char::is_whitespace) {
        patterns.push("bare_first");
    }
    if value.chars().next().is_some_and(|ch| ch.is_lowercase())
        && !value.chars().any(char::is_uppercase)
    {
        patterns.push("lowercase");
    }
    if url_ranges(text)
        .iter()
        .any(|(start, end)| span.start >= *start && span.end <= *end)
    {
        patterns.push("url");
    }
    let line_start = text[..span.start].rfind('\n').map(|at| at + 1).unwrap_or(0);
    let line = text[line_start..span.end].to_lowercase();
    if GREETING_MARKERS.iter().any(|marker| line.contains(marker)) {
        patterns.push("greeting");
    }
    if line.split_whitespace().count() <= 12
        && CLOSING_MARKERS.iter().any(|marker| line.contains(marker))
    {
        patterns.push("signoff");
    }
    let previous_start = text[..line_start]
        .trim_end_matches('\n')
        .rfind('\n')
        .map(|at| at + 1)
        .unwrap_or(0);
    let window = text[previous_start..span.end].to_lowercase();
    if window.contains("ps:") || window.contains("ps :") || window.contains("p.s.") {
        patterns.push("ps");
    }
    if REPLY_MARKERS.iter().any(|marker| line.contains(marker)) {
        patterns.push("wrote");
    }
    patterns
}

/// Count union spans whose exact value is a public term (never a person).
pub(crate) fn trap_fp(spans: &[GoldSpan], text: &str, public: &PublicTerms) -> usize {
    spans
        .iter()
        .filter(|span| span.kind != EntityKind::Person && span.start < span.end)
        .filter(|span| public.contains(&text[span.start..span.end]))
        .count()
}

#[derive(Default)]
pub(crate) struct PatternScore {
    pub(crate) gold: usize,
    pub(crate) recalled: usize,
}
