//! The reference term list, checked against the lexicon it belongs to.

use super::helpers::masked;
use kernel_privacy::{Anonymizer, Registry};

/// The reference list: a table of conditions, drugs and Art. 9 categories with
/// their forms in six languages (see its header for the sources).
const REFERENCE: &str = include_str!("../../data/sensitive-terms-reference.md");

/// The lexicon the reference list must be a part of.
const LEXICON_ROWS: &str = include_str!("../../data/sensitive-terms-v1.tsv");

/// The cue word that makes a sentence a health sentence in each language.
fn reference_cue(lang: &str) -> &'static str {
    match lang {
        "af" => "pasiënt",
        "hu" => "beteg",
        "sl" => "bolnik",
        "zh" => "患者",
        _ => "patient",
    }
}

#[test]
fn every_reference_term_is_a_lexicon_row_and_is_masked_in_its_language() {
    use std::collections::HashSet;
    let registry = Registry::new();
    let rows: HashSet<&str> = LEXICON_ROWS.lines().collect();
    let languages = [
        ("en", 3),
        ("fr", 4),
        ("af", 5),
        ("hu", 6),
        ("sl", 7),
        ("zh", 8),
    ];
    let mut per_language = [0usize; 6];
    let mut drugs = 0usize;
    let check = |category: &str, lang: &str, term: &str| {
        // A Hungarian form with the accent rák is the accent rule in code, not a row.
        if !(lang == "hu" && term.contains("rák")) {
            // A cue-gated form (a `?` row, as for a bare Slovene rak) is a row too.
            let row = format!("{category}\t{lang}\t{term}");
            let gated = format!("{category}\t{lang}\t?{term}");
            assert!(
                rows.contains(row.as_str()) || rows.contains(gated.as_str()),
                "reference row missing from the lexicon: {row}"
            );
        }
        let sentence = format!("{}: {term}.", reference_cue(lang));
        let spans = registry.analyze(&sentence);
        let out = Anonymizer::new([0x4B; 32]).anonymize(&sentence, &spans).0;
        assert!(!out.contains(term), "{term} ({lang}) left in clear: {out}");
        assert!(
            out.contains(&format!("{category}_")),
            "no {category} token for {term} ({lang}): {out}"
        );
    };
    for line in REFERENCE.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        match cells.get(1).and_then(|id| id.chars().next()) {
            Some('C') | Some('A') if cells.len() >= 9 => {
                for (index, (lang, column)) in languages.iter().enumerate() {
                    let term = cells[*column];
                    if term != "—" {
                        per_language[index] += 1;
                        check(cells[2], lang, term);
                    }
                }
            }
            Some('D') if cells.len() >= 4 => {
                drugs += 1;
                check("HEALTH", "xx", cells[3]);
            }
            _ => {}
        }
    }
    for (index, (lang, _)) in languages.iter().enumerate() {
        assert!(
            per_language[index] >= 120,
            "{lang}: only {} reference terms",
            per_language[index]
        );
    }
    assert!(drugs >= 40, "only {drugs} drug names");
}

/// The Han fold table: a traditional character, its simplified form, and the OpenCC
/// file the pair came from (TS: traditional to simplified, ST: simplified to
/// traditional).
const HAN_FOLD_TABLE: &str = include_str!("../../data/han-fold-v1.tsv");

#[test]
fn every_zh_reference_term_in_traditional_is_masked() {
    use std::collections::HashMap;
    let mut simplified_to_traditional: HashMap<char, char> = HashMap::new();
    for line in HAN_FOLD_TABLE.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        if let [traditional, simplified, "ST"] = fields[..] {
            if let (Some(t), Some(s)) = (traditional.chars().next(), simplified.chars().next()) {
                simplified_to_traditional.entry(s).or_insert(t);
            }
        }
    }
    assert!(
        simplified_to_traditional.len() >= 80,
        "the fold table has {} ST pairs",
        simplified_to_traditional.len()
    );
    let to_traditional = |simplified: &str| -> String {
        simplified
            .chars()
            .map(|ch| simplified_to_traditional.get(&ch).copied().unwrap_or(ch))
            .collect()
    };
    for (simplified, traditional) in [
        ("偏头痛", "偏頭痛"),
        ("惊恐障碍", "驚恐障礙"),
        ("创伤后应激障碍", "創傷後應激障礙"),
        ("医疗证明", "醫療證明"),
    ] {
        assert_eq!(to_traditional(simplified), traditional);
    }
    let mut checked = 0;
    for line in REFERENCE.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 9
            || !matches!(
                cells.get(1).and_then(|id| id.chars().next()),
                Some('C') | Some('A')
            )
        {
            continue;
        }
        let zh = cells[8];
        if zh == "—" {
            continue;
        }
        let traditional = to_traditional(zh);
        let out = masked(&format!("患者: {traditional}。"));
        assert!(
            !out.contains(&traditional),
            "{zh} ({traditional}) left in clear: {out}"
        );
        assert!(
            out.contains(&format!("{}_", cells[2])),
            "no {} token for {traditional}: {out}",
            cells[2]
        );
        checked += 1;
    }
    assert!(checked >= 120, "only {checked} zh reference terms checked");
}
