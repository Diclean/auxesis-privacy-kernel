//! The decoded view: its offset map, its markers and the tokens it leaves.

use super::super::{DecodedText, MAX_PASSES};
use super::decode;

#[test]
fn source_bounds_map_back_to_exact_bytes() {
    let source = "Hi&nbsp;Tobi";
    let decoded = DecodedText::new(source);
    let start = decoded.text().find("Tobi").expect("name");
    let (begin, end) = decoded.source_bounds(start, start + 4).expect("maps back");
    assert_eq!(&source[begin..end], "Tobi");
    let nbsp = decoded.text().find('\u{00A0}').expect("space");
    let (begin, end) = decoded
        .source_bounds(nbsp, nbsp + '\u{00A0}'.len_utf8())
        .expect("maps entity");
    assert_eq!(&source[begin..end], "&nbsp;");
}

#[test]
fn markers_and_hidden_characters_are_dropped_and_mapped_back() {
    let source = "sk-abc&#10214;PERSON_ABCDEFABCDEF&#10215;def\u{200B}g&shy;h⟦⟦X⟧i⟧";
    let decoded = DecodedText::new(source);
    assert_eq!(decoded.text(), "sk-abcdefghi");
    // The decoded value maps back to every source byte, markers included.
    assert_eq!(decoded.source_bounds(0, 12), Some((0, source.len())));
    // Any pair goes, to the nearest `⟧`; the bracket-only view keeps its content.
    let long = format!("chimioth⟦{}⟧érapie a⟦A B⟧b", "A".repeat(65));
    assert_eq!(decode(&long), "chimiothérapie ab");
    let kept = DecodedText::brackets_only("a⟦A B⟧b");
    assert_eq!(kept.text(), "aA Bb");
    // Invisible named entities, `&shy` before a long run, short names only with `;`.
    let source = format!("a&ZeroWidthSpace;b&ZWJ;c&it;d&shy{}", "e".repeat(40));
    assert_eq!(decode(&source), format!("abcd{}", "e".repeat(40)));
    assert_eq!(decode("a&itb"), "a&itb");
    assert_eq!(decode("a⟧b⟧c"), "abc");
}

#[test]
fn every_dropped_marker_maps_to_its_source_range() {
    let source = "a⟦X⟧b ⟧c &#x27E6;Y&#x27E7;d ⟦e";
    let decoded = DecodedText::new(source);
    let markers: Vec<&str> = decoded
        .markers()
        .iter()
        .map(|&(start, end)| &source[start..end])
        .collect();
    assert_eq!(markers, ["⟦X⟧", "⟧", "&#x27E6;Y&#x27E7;", "⟦"]);
}

#[test]
fn nesting_past_the_cap_fails_closed_on_the_whole_token() {
    let source = format!("check sk&{}#45;abc, please", "amp;".repeat(MAX_PASSES));
    let decoded = DecodedText::new(&source);
    // The token runs from whitespace to whitespace, its comma included.
    assert_eq!(decoded.unresolved(), [(6, source.len() - 7)]);
    // One layer less folds: nothing is unresolved.
    let source = format!("sk&{}#45;abc", "amp;".repeat(MAX_PASSES - 2));
    assert_eq!(DecodedText::new(&source).text(), "sk-abc");
    assert!(DecodedText::new(&source).unresolved().is_empty());
}

#[test]
fn url_segments_split_on_url_separators() {
    let source = "see https://linkedin.example.invalid/in/jules-ferrand?name=ana%2Bmaria";
    let segments = DecodedText::url_segments(source);
    let values: Vec<&str> = segments
        .iter()
        .map(|(value, _, _)| value.as_str())
        .collect();
    assert!(values.contains(&"jules"));
    assert!(values.contains(&"ferrand"));
    assert!(values.contains(&"ana"));
    assert!(values.contains(&"maria"));
    for (value, start, end) in &segments {
        assert_eq!(&source[*start..*end], value.as_str());
    }
}
