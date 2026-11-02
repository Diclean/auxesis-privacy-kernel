//! An IBAN glued to letters on both sides and broken
//! between the country code and the check digits is one value and must be
//! hidden. Invented/public specimen only.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, masked, MODES};
use kernel_core::privacy::PrivacyMode;

/// The GB specimen split between the country code and the check digits, with a
/// letter glued on each side: `xyGB\n82WEST…ok`.
fn wrapped_glued(compact: &str) -> String {
    format!("xy{}\n{}ok", &compact[..2], &compact[2..])
}

#[test]
fn glued_and_wrapped_gb_iban_is_hidden_in_both_modes() {
    // FAKE: the public GB specimen in a shape an earlier version missed.
    let compact = "GB82WEST12345698765432";
    for value in [
        wrapped_glued(compact),
        wrapped_glued(&compact.to_lowercase()),
    ] {
        let start = value.find(['G', 'g']).expect("value");
        let end = start + compact.len() + 1;
        for mode in MODES {
            let ranges = masked(mode, &value).expect("gate allows");
            assert!(
                covered(&ranges, start, end),
                "{mode:?} leaves the glued and wrapped IBAN clear: {value:?}: {ranges:?}"
            );
        }
    }
}

#[test]
fn checksum_invalid_lookalike_in_the_same_shape_stays_clear() {
    // FAKE: one check digit changed; the same glue and wrap must stay clear.
    let text = "xyGB\n83WEST12345698765432ok";
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        assert!(
            masked(mode, text).expect("gate allows").is_empty(),
            "{mode:?} masked an invalid IBAN lookalike: {text:?}"
        );
    }
}

#[test]
fn ordinary_prose_gb_break_digits_stay_clear() {
    // No bank cue and a value that fails mod-97: nothing here is an IBAN.
    let text = "The spare part gb\n46234567890123456789 is on the shelf.";
    for mode in MODES {
        assert!(
            masked(mode, text).expect("gate allows").is_empty(),
            "{mode:?} masked ordinary prose: {text:?}"
        );
    }
}
