//! Tests for the default caps and the warning line.

use super::super::*;

#[test]
fn pricey_limits_do_not_overflow_the_warning_line() {
    assert_eq!(
        warning_threshold(u64::MAX),
        (u64::MAX as u128 * 8 / 10) as u64
    );
    assert_eq!(warning_threshold(1000), 800);
    assert_eq!(warning_threshold(5), 4);
    assert_eq!(warning_threshold(0), 0);
}
