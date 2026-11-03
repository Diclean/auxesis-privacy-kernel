//! Germany: the Steuer-ID, and the full-width spelling of a value.

use kernel_privacy::recognizers::eu_ids::DeSteuerIdRecognizer;
use kernel_privacy::Recognizer;

use super::helpers::wide;

/// The full-width spelling of a value reads like the plain one.
#[test]
fn a_full_width_value_reads_like_the_plain_one() {
    assert_eq!(wide("26954371827"), "２６９５４３７１８２７");
    let text = wide("26954371827");
    let spans = DeSteuerIdRecognizer::new().analyze(&text);
    assert_eq!(spans.len(), 1, "{spans:?}");
    assert_eq!(
        &text[spans[0].start..spans[0].end],
        "２６９５４３７１８２７"
    );
}
