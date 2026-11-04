//! The label lexicon: classes, labels, the automaton and the blood-column label check.

use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, MatchKind};

use super::text::{fold, is_cjk};

pub(super) const DATA: &str = include_str!("../../../data/label-value-v1.tsv");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    Secret,
    Cookie,
    Id,
    Health,
    Blood,
    Member,
}

pub(super) struct Label {
    pub(super) class: Class,
    /// Only after `:`, `=`, `#` or a number word.
    pub(super) punct: bool,
    /// Only when a number word comes first (`licence no.`).
    pub(super) numbered: bool,
    pub(super) cjk_start: bool,
    pub(super) cjk_end: bool,
}

pub(super) struct Lexicon {
    pub(super) automaton: AhoCorasick,
    pub(super) labels: Vec<Label>,
}

pub(super) static LEXICON: LazyLock<Lexicon> = LazyLock::new(|| {
    let (mut patterns, mut labels) = (Vec::new(), Vec::new());
    for line in DATA
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split('\t').collect();
        let [_, class, link, label] = cols[..] else {
            panic!("label-value-v1.tsv: four columns: {line:?}")
        };
        let class = match class {
            "SECRET" => Class::Secret,
            "COOKIE" => Class::Cookie,
            "ID" => Class::Id,
            "HEALTH" => Class::Health,
            "BLOOD" => Class::Blood,
            "MEMBER" => Class::Member,
            _ => panic!("label-value-v1.tsv: class {class:?}"),
        };
        let label = fold(label).0;
        let cjk = |ch: Option<char>| ch.is_some_and(is_cjk);
        labels.push(Label {
            class,
            punct: link == "punct",
            numbered: link == "number",
            cjk_start: cjk(label.chars().next()),
            cjk_end: cjk(label.chars().last()),
        });
        patterns.push(label);
    }
    let automaton = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(&patterns)
        .expect("label-value lexicon builds");
    Lexicon { automaton, labels }
});

/// Whether a header cell is a blood-group label, whole (`blood_type`, `Groupe sanguin`).
pub(super) fn is_blood_label(cell: &str) -> bool {
    let lexicon = &*LEXICON;
    let folded = fold(cell).0;
    lexicon.automaton.find(&folded).is_some_and(|hit| {
        hit.start() == 0
            && hit.end() == folded.len()
            && lexicon.labels[hit.pattern().as_usize()].class == Class::Blood
    })
}
