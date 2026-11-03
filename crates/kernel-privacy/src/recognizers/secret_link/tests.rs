//! Shared fixtures and helpers for the secret-link scanner tests.

use std::time::Duration;

use proptest::prelude::*;

use crate::recognizer::Recognizer;
use crate::recognizers::secrets::SecretRecognizer;

use super::lex::is_sentinel;
use super::link_scan;
use super::scan::scan;

mod linear;
mod scanner;

mod timing {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/timing.rs"
    ));
}

include!("../../../tests/data/secret_tail4_cases.rs");

/// The 21 must-stay-clear pins: `link_scan` adds nothing to them.
const CLEAR: &[&str] = &[
    "I forgot my password",
    "password reset link sent",
    "PIN code required at checkout",
    "what is a strong password?",
    "the code is on GitHub",
    "the door code is on the fridge note",
    "the token for the event is free",
    "The pass is valid until Monday.",
    "The pass to the museum is on the table.",
    "The code is clean and fast.",
    "Our team code review is on Friday.",
    "the password policy requires 12 characters",
    "mot de passe oublié ?",
    "Kérem a jelszó visszaállítását",
    "geslo je pozabljeno",
    "忘记密码了",
    "bypass: Fk3jQ9xZ2m",
    "pwd=abc",
    "The ~~password~~ hint is in the vault.",
    "The `password` field is required.",
    "The __pwd__ command prints the folder.",
];

/// The fastest of nine runs of `link_scan` over `text`, after one warm-up.
/// A loaded machine or a debug build on a shared runner must not decide a
/// bound: what is measured is the work, not the scheduler. The bound itself
/// is unchanged.
fn fastest(text: &str) -> Duration {
    timing::fastest(|| {
        let _ = link_scan(text);
    })
}

/// P1: well-formed spans; P7: main's masked bytes are a subset of the head's.
fn p1_and_p7(text: &str) -> Result<(), TestCaseError> {
    let spans = link_scan(text);
    for (index, &(start, end)) in spans.iter().enumerate() {
        prop_assert!(
            start < end
                && end <= text.len()
                && text.is_char_boundary(start)
                && text.is_char_boundary(end)
        );
        prop_assert!(
            index == 0 || spans[index - 1].1 < start,
            "unsorted or overlapping: {spans:?}"
        );
        prop_assert!(
            !text[start..end].starts_with(char::is_whitespace)
                && !text[start..end].ends_with(char::is_whitespace)
        );
    }
    let cover = |spans: Vec<crate::span::Span>| {
        let mut bytes = vec![false; text.len()];
        spans
            .iter()
            .for_each(|span| bytes[span.start..span.end].fill(true));
        bytes
    };
    let (main, head) = (
        cover(SecretRecognizer::main_spans(text)),
        cover(SecretRecognizer::new().analyze(text)),
    );
    prop_assert!(
        main.iter().zip(&head).all(|(main, head)| !main || *head),
        "lost a byte of main: {text:?}"
    );
    Ok(())
}

/// The masked chars of `link_scan`, by char index.
fn by_char(text: &str) -> Vec<bool> {
    let mut bytes = vec![false; text.len()];
    link_scan(text)
        .iter()
        .for_each(|&(start, end)| bytes[start..end].fill(true));
    text.char_indices().map(|(at, _)| bytes[at]).collect()
}

/// P6: U+E000 and U+FFFD are `x` for every class test and every length cap.
fn p6(text: &str) -> Result<(), TestCaseError> {
    let x: String = text
        .chars()
        .map(|ch| if is_sentinel(ch) { 'x' } else { ch })
        .collect();
    prop_assert_eq!(by_char(text), by_char(&x), "{:?}", text);
    Ok(())
}

/// P4: the PR2 spans hold the PR1 spans, and mask each key-column cell.
fn p4(text: &str, hide: &[std::ops::Range<usize>]) -> Result<(), TestCaseError> {
    let cover = |tables: bool| {
        let mut bytes = vec![false; text.len()];
        scan(text, tables)
            .iter()
            .for_each(|&(start, end)| bytes[start..end].fill(true));
        bytes
    };
    let (pr1, pr2) = (cover(false), cover(true));
    prop_assert!(
        pr1.iter().zip(&pr2).all(|(pr1, pr2)| !pr1 || *pr2),
        "lost a PR1 byte: {text:?}"
    );
    for range in hide {
        prop_assert!(
            pr2[range.clone()].iter().all(|&masked| masked),
            "{text:?} {range:?}"
        );
    }
    p1_and_p7(text)
}

const ALPHABET: &[&str] = &[
    "|",
    "-",
    ":",
    "=",
    "\"",
    "'",
    "“",
    "”",
    "„",
    "«",
    "»",
    "‹",
    "›",
    "‘",
    "’",
    "「",
    "」",
    "\\",
    "`",
    "~",
    "#",
    "[",
    "]",
    "{",
    "}",
    ".",
    "!",
    "?",
    "…",
    "。",
    "\n",
    "\r",
    "\t",
    " ",
    "\u{A0}",
    "\u{200B}",
    "\u{2028}",
    "\u{E000}",
    "\u{FFFD}",
    "é",
    "\u{300}",
    "*",
    "_",
    "password",
    "pin",
    "token",
    "mot de passe",
    "mdp",
    "密码",
    "is",
    "est",
    "是",
    "for",
    "a",
    "abcd",
    "x",
];
