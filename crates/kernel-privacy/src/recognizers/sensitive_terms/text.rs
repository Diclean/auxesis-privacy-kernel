//! Word splitting and Unicode folding for lexicon matching.

use std::sync::OnceLock;

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

use crate::contacts::fold::{homoglyph, is_cyrillic, is_default_ignorable, is_greek};

/// A maximal run of letters and digits, folded for matching.
pub(super) struct Word {
    pub(super) folded: String,
    pub(super) start: usize,
    pub(super) end: usize,
}

/// Split `text` into its words. Invisible and combining characters belong to
/// the word around them, and every other character ends a word.
pub(super) fn words(text: &str) -> Vec<Word> {
    let mut words = Vec::new();
    let mut current: Option<Word> = None;
    for (offset, ch) in text.char_indices() {
        let end = offset + ch.len_utf8();
        if is_default_ignorable(ch) || is_combining_mark(ch) {
            if let Some(word) = current.as_mut() {
                word.end = end;
            }
        } else if ch.is_alphanumeric() && !is_han(ch) {
            let word = current.get_or_insert(Word {
                folded: String::new(),
                start: offset,
                end,
            });
            fold_into(&mut word.folded, ch);
            word.end = end;
        } else if let Some(word) = current.take() {
            words.push(word);
        }
    }
    words.extend(current);
    for word in &mut words {
        if let Some(folded) = lookalike_fold(&text[word.start..word.end]) {
            word.folded = folded;
        }
    }
    words
}

/// A Latin word written with Cyrillic or Greek look-alikes (`DIАВЕТЕS`), folded
/// with each look-alike read as its Latin letter. `None` for a
/// word with no ASCII letter, no Cyrillic or Greek letter, or a letter that has
/// no Latin look-alike: a Cyrillic or Greek word keeps its letters.
fn lookalike_fold(raw: &str) -> Option<String> {
    let foreign = |ch: char| is_cyrillic(ch) || is_greek(ch);
    if !raw.chars().any(|ch| ch.is_ascii_alphabetic()) || !raw.chars().any(foreign) {
        return None;
    }
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if foreign(ch) {
            let mut lower = ch.to_lowercase();
            let single = lower.next().filter(|_| lower.next().is_none());
            fold_into(
                &mut out,
                homoglyph(ch).or_else(|| single.and_then(homoglyph))?,
            );
        } else if !is_default_ignorable(ch) {
            fold_into(&mut out, ch);
        }
    }
    Some(out)
}

/// The traditional-to-simplified pairs of the Han terms, from OpenCC (see the
/// header of `data/han-fold-v1.tsv`), sorted by the traditional character. Both
/// sides are three bytes in UTF-8, so a folded text keeps every byte offset.
const HAN_FOLD_DATA: &str = include_str!("../../../data/han-fold-v1.tsv");

/// The parsed, sorted table, built once.
pub(super) fn han_fold_pairs() -> &'static [(char, char)] {
    static PAIRS: OnceLock<Vec<(char, char)>> = OnceLock::new();
    PAIRS.get_or_init(|| {
        // A traditional character with two simplified forms keeps its TS pair: the
        // fold reads traditional as simplified, so TS is the authority (rank 0).
        let mut ranked: Vec<(char, char, u8)> = HAN_FOLD_DATA
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| {
                let mut fields = line.split('\t');
                let traditional = fields.next()?.chars().next()?;
                let simplified = fields.next()?.chars().next()?;
                let rank = if fields.next() == Some("ST") { 1 } else { 0 };
                Some((traditional, simplified, rank))
            })
            .collect();
        ranked.sort_unstable_by_key(|&(traditional, _, rank)| (traditional, rank));
        ranked.dedup_by_key(|&mut (traditional, _, _)| traditional);
        ranked
            .into_iter()
            .map(|(traditional, simplified, _)| (traditional, simplified))
            .collect()
    })
}

/// The simplified form of `ch`, or `ch` itself when it has none in the table.
fn han_fold(ch: char) -> char {
    let pairs = han_fold_pairs();
    pairs
        .binary_search_by_key(&ch, |&(traditional, _)| traditional)
        .map_or(ch, |index| pairs[index].1)
}

/// The Han text as the Han terms read it: a traditional character reads as its
/// simplified form, and an invisible character or a space is dropped, so
/// `糖\u{200B}尿 病` reads `糖尿病`. Each kept character remembers where it sits in
/// the original text.
pub(super) struct HanView {
    pub(super) text: String,
    /// Per kept character: its byte span in `text`, then in the original.
    cuts: Vec<(usize, usize, usize, usize)>,
}

impl HanView {
    pub(super) fn new(text: &str) -> Self {
        let mut view = HanView {
            text: String::with_capacity(text.len()),
            cuts: Vec::new(),
        };
        for (start, ch) in text.char_indices() {
            if is_default_ignorable(ch) || ch.is_whitespace() || is_han_joiner(ch) {
                continue;
            }
            let from = view.text.len();
            view.text.push(han_fold(ch));
            view.cuts
                .push((from, view.text.len(), start, start + ch.len_utf8()));
        }
        view
    }

    /// The original byte span of the view span `start..end`, when both ends
    /// fall on kept characters (a Han match always does).
    pub(super) fn original(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        let first = self.cuts.binary_search_by_key(&start, |cut| cut.0).ok()?;
        let last = self.cuts.binary_search_by_key(&end, |cut| cut.1).ok()?;
        Some((self.cuts[first].2, self.cuts[last].3))
    }
}

/// Punctuation that a Han term may be split by, as in 糖·尿·病 or 糖-尿-病: middle
/// dots and the hyphen family. The view drops it, so the term still matches.
fn is_han_joiner(ch: char) -> bool {
    matches!(ch, '·' | '・' | '･' | '‧' | '-' | '‐' | '‑' | '–' | '—')
}

/// Whether `ch` is a Han ideograph. Han characters end a Latin word.
pub(super) fn is_han(ch: char) -> bool {
    matches!(
        ch as u32,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x2_0000..=0x2_EBEF
    )
}

/// Append the matching form of `ch`: NFKD, combining marks dropped, lowercase.
fn fold_into(out: &mut String, ch: char) {
    for decomposed in ch.nfkd() {
        if !is_combining_mark(decomposed) {
            out.extend(decomposed.to_lowercase());
        }
    }
}

/// The matching form of a whole string.
pub(super) fn fold_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        fold_into(&mut out, ch);
    }
    out
}

/// Whether the text between two consecutive words is a join a multi-word term
/// may cross: whitespace, a hyphen, an apostrophe or an invisible character.
pub(super) fn joins(text: &str, from: usize, to: usize) -> bool {
    from < to
        && text[from..to].chars().all(|ch| {
            ch.is_whitespace()
                || is_default_ignorable(ch)
                || matches!(ch, '-' | '\'' | '\u{2019}' | '\u{02BC}')
        })
}
