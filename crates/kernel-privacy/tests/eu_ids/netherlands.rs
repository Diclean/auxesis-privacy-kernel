//! The Netherlands: the BSN, nine consecutive digits.

use super::helpers::assert_value_hidden_in_both_modes;

/// EU-KERNEL-1b-1 (seal P3): a labelled BSN printed in groups is a BSN.
#[test]
fn a_labelled_bsn_in_groups_is_hidden() {
    for (text, value) in [
        ("BSN 456 789 236", "456 789 236"),
        ("burgerservicenummer: 456.789.236", "456.789.236"),
        ("citizen service number 456 789 236", "456 789 236"),
    ] {
        assert_value_hidden_in_both_modes(text, value);
    }
}
