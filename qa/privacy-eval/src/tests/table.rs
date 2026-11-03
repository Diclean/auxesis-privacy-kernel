//! Tests for the table primitives.

use crate::table::*;

#[test]
fn header_matches_the_spec_shape() {
    assert_eq!(
        row_line("measure", "value", "bar", "status"),
        "measure                                   value     bar        status"
    );
}

#[test]
fn a_missed_bar_prints_missed_and_is_never_rounded_up() {
    // 99.49 % is below the 99.5 % bar: it must print MISSED, not 99.50/MET.
    let value = hundredths(9949, 10000).expect("a non-empty tally has a rate");
    assert_eq!(value, 9949);
    assert_eq!(pct(value), "99.49 %");
    assert_eq!(met(value, BAR_C_HUNDREDTHS), "MISSED");
    let line = row_line(
        "Tier C recall, held-out",
        &pct(value),
        ">= 99.5 %",
        met(value, BAR_C_HUNDREDTHS),
    );
    assert!(line.contains("99.49 %"), "{line}");
    assert!(!line.contains("99.50"), "{line}");
    assert!(line.ends_with(">= 99.5 %  MISSED"), "{line}");
    let at = hundredths(9950, 10000).expect("a non-empty tally has a rate");
    assert_eq!(met(at, BAR_C_HUNDREDTHS), "MET");
}
