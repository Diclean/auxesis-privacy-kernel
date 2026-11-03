//! HTML entity references: names, numeric values and their fixed point.

use super::super::entities;
use super::decode;

#[test]
fn named_and_numeric_entities_decode() {
    assert_eq!(decode("Hi&nbsp;Tobi"), "Hi\u{00A0}Tobi");
    assert_eq!(decode("a&amp;b"), "a&b");
    assert_eq!(decode("caf&#233;"), "café");
    assert_eq!(decode("caf&#xe9;"), "café");
    assert_eq!(decode("&eacute;lodie"), "élodie");
    // An unknown entity keeps its bytes.
    assert_eq!(decode("a&unknown;b"), "a&unknown;b");
    assert_eq!(decode("a & b"), "a & b");
}

#[test]
fn numeric_references_follow_html5() {
    assert_eq!(decode("sk&#0045pq&#X02d;pq&#x2Dpq"), "sk-pq-pq-pq");
    // Zero, surrogates and out-of-range values read U+FFFD; C1 values read
    // their Windows-1252 character.
    assert_eq!(
        decode("a&#0;b&#xD800;c&#99999999999;d"),
        "a\u{FFFD}b\u{FFFD}c\u{FFFD}d"
    );
    assert_eq!(decode("a&#150;b"), "a–b");
    // `&#` with no digit stays literal.
    assert_eq!(decode("a&#;b&#x;c"), "a&#;b&#x;c");
    // Named entities match in any case; nested encodings fold to a fixed point.
    assert_eq!(
        decode("a&AMP;b R&D chimioth&AMP;eacute;rapie"),
        "a&b R&D chimiothérapie"
    );
    assert_eq!(decode("sk&#38;#38;#x2d;x"), "sk-x");
}

#[test]
fn every_html5_name_decodes_and_only_legacy_names_need_no_semicolon() {
    for table in [entities::ENTITIES, entities::FOLDED] {
        assert!(table.windows(2).all(|pair| pair[0].0 < pair[1].0));
    }
    assert_eq!(entities::ENTITIES.len(), 2125);
    assert_eq!(
        decode("plju&ccaron;ni PLJU&Ccaron;NI &CCARON;"),
        "pljučni PLJUČNI č"
    );
    assert_eq!(decode("t&uuml;d&odblac;gyullad&aacute;s"), "tüdőgyulladás");
    assert_eq!(decode("a&NotEqualTilde;b&fjlig;c"), "a\u{2242}\u{338}bfjc");
    // The longest legacy name without `;`; others stay literal.
    assert_eq!(
        decode("&notit; &noti &eacutex &ccaron &ensp"),
        "¬it; ¬i éx &ccaron \u{2002}"
    );
    assert_eq!(decode("a&pi b&pi;"), "a&pi bπ");
}
