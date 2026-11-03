//! Shared fixtures plus the signature-walk regression for the e-mail layer.

mod policy;
mod seeding;
mod structure;

use crate::span::{EntityKind, Span};

use super::display::is_closing;
use super::lines::{line_ranges, word_tokens};
use super::signals::{is_ps_or_nb_line, is_signature_or_header_range};
use super::EmailLayer;

/// GATE-PERF-1: the signature-block check as it was on main, one split of
/// the whole text per call. The upward walk must answer exactly the same.
fn signature_or_header_range_main(text: &str, start: usize, end: usize) -> bool {
    let line_start = text[..start].rfind('\n').map(|at| at + 1).unwrap_or(0);
    let lines = line_ranges(text);
    let mut seen = 0usize;
    for (above_start, above_end) in lines.iter().rev() {
        if *above_start >= line_start {
            continue;
        }
        let candidate = text[*above_start..*above_end].trim();
        if candidate.is_empty() {
            continue;
        }
        seen += 1;
        if seen > 6 {
            break;
        }
        if matches!(candidate, "--" | "---" | "—" | "––")
            || (word_tokens(candidate).len() <= 6 && is_closing(candidate))
            || is_ps_or_nb_line(candidate)
        {
            return true;
        }
    }
    // The line-local checks did not change: run them on the same text.
    let line_end = text[start..].find('\n').map_or(text.len(), |at| start + at);
    let line = &text[line_start..line_end];
    let local = format!("{line}\n");
    let shift = start - line_start;
    is_signature_or_header_range(&local, shift, shift + (end - start))
}

#[test]
fn upward_signature_walk_answers_what_the_whole_text_split_did() {
    let mut texts: Vec<String> = [
        include_str!("../../tests/data/secret_2_tables_main.txt"),
        include_str!("../../tests/data/secret_2_main.txt"),
        include_str!("../../tests/data/health_label_main.txt"),
        include_str!("../../tests/data/address_main.txt"),
        include_str!("../../tests/data/fin6_main.txt"),
        include_str!("../../tests/data/label_value_main.txt"),
    ]
    .iter()
    .map(|text| text.chars().take(24 * 1024).collect())
    .collect();
    texts.push(
        "Hi Mila,\r\nthanks.\r\n\r\nBest regards,\r\n\r\n  \r\nJules\nP.S. Noor\n\
             --\nOwen Calder\n\n\n\na\nb\nc\nd\ne\nf\ng\nLeila, ok\n—\nSam\n\nCheers\nAva, hi"
            .to_string(),
    );
    for (head, unit) in [
        ("", "id,password,note\n"),
        ("", "\nid,password,note\n"),
        ("id,password,city\n", "\nalice,hunter,oslo\n"),
        ("id,password,note\n", "17,\"ordered\nagain\",x\n"),
        ("id,password,note\n", "\nThe meeting moved to Tuesday.\n"),
        ("id,password,note\n", "17,Cherry6!,\n,,\nThanks,\n"),
    ] {
        texts.push(format!("{head}{}", unit.repeat(200)));
    }
    let mut checked = 0usize;
    let mut kept = 0usize;
    for text in &texts {
        for (start, end) in line_ranges(text) {
            // One word at the line start (or the whole line when it is short).
            let word = text[start..end]
                .find([' ', ',', '\r'])
                .map_or(end, |at| start + at.max(1));
            if !text.is_char_boundary(word) || word <= start {
                continue;
            }
            let head = is_signature_or_header_range(text, start, word);
            assert_eq!(
                head,
                signature_or_header_range_main(text, start, word),
                "line {start}..{end}: {:?}",
                &text[start..end]
            );
            checked += 1;
            kept += usize::from(head);
        }
    }
    assert!(checked > 1_500, "only {checked} lines checked");
    assert!(kept > 5, "the sample keeps only {kept} signature lines");
}

fn persons(text: &str) -> Vec<String> {
    persons_with(text, false)
}

/// The person spans of the layer with the bare-first-name switch set.
fn persons_with(text: &str, mask_first_names: bool) -> Vec<String> {
    EmailLayer::new()
        .with_first_names(mask_first_names)
        .analyze(text)
        .into_iter()
        .filter(|span| span.kind == EntityKind::Person)
        .map(|span| text[span.start..span.end].to_string())
        .collect()
}

/// Whether a lone model `PERSON` span covering `value` survives the layer.
fn kept_gliner_person(text: &str, value: &str, mask_first_names: bool) -> bool {
    let start = text.find(value).expect("value in text");
    let span = Span::new(
        EntityKind::Person,
        start,
        start + value.len(),
        0.9,
        "gliner",
    );
    let layer = EmailLayer::new().with_first_names(mask_first_names);
    let kept = layer.apply(text, vec![span], &[span]);
    kept.iter().any(|candidate| {
        candidate.kind == EntityKind::Person
            && candidate.start <= start
            && candidate.end >= start + value.len()
    })
}
