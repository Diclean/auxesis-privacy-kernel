//! Han folding and Han term matching.

use super::super::text::{han_fold_pairs, HanView};
use super::hits;

#[test]
fn the_han_fold_table_is_sorted_and_keeps_byte_offsets() {
    let pairs = han_fold_pairs();
    assert!(!pairs.is_empty());
    assert!(pairs.windows(2).all(|pair| pair[0].0 < pair[1].0));
    for &(traditional, simplified) in pairs {
        assert_eq!(traditional.len_utf8(), 3);
        assert_eq!(simplified.len_utf8(), 3);
    }
    assert_eq!(HanView::new("憂鬱症").text, "忧郁症");
}

#[test]
fn a_han_term_matches_inside_a_run_of_characters() {
    assert_eq!(hits("他的糖尿病复发了。"), vec!["糖尿病"]);
}
