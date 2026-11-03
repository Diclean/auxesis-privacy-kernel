//! Belgium: the national number, and the check of a birth after 2000.

use kernel_privacy::recognizers::eu_ids::BeNationalNumberRecognizer;
use kernel_privacy::Recognizer;

use super::helpers::assert_hidden_in_both_modes;

/// The Belgian check of a birth after 2000 is computed on the number with the
/// century in front.
#[test]
fn the_belgian_century_in_front_carries_its_own_check() {
    for value in ["05031423780", "99.03.14-237.17", "299.03.14-237.17"] {
        assert_hidden_in_both_modes(value);
        let spans = BeNationalNumberRecognizer::new().analyze(value);
        assert!(
            spans
                .iter()
                .any(|span| span.start == 0 && span.end == value.len()),
            "{value:?} -> {spans:?}"
        );
    }
}
