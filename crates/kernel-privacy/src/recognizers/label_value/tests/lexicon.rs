use super::super::fold;
use super::super::lexicon::{DATA, LEXICON};

#[test]
fn every_lexicon_line_parses_and_folds_to_itself() {
    for line in DATA
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let label = line.rsplit('\t').next().unwrap();
        assert_eq!(fold(label).0, label, "write {label:?} folded");
    }
    assert!(LEXICON.labels.len() > 150);
}
