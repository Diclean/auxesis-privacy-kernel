//! Digits from the newer Unicode decimal blocks fold to ASCII before the
//! detectors, so an IBAN, a card or a phone written in them is found exactly
//! as its ASCII form is. Fake values only.

use kernel_privacy::{Anonymizer, EntityKind, Registry};

/// Zero code points of blocks the privacy table lacked before the union:
/// Garay (U+10D40), Kawi (U+11F50), Gurung Khema (U+16130) and Myanmar
/// Extended-C (U+116D0).
const SCRIPT_ZEROS: [u32; 4] = [0x10D40, 0x11F50, 0x16130, 0x116D0];

const SAMPLES: [(&str, EntityKind); 3] = [
    ("IBAN DE89 3704 0044 0532 0130 00", EntityKind::Iban),
    ("card 4111 1111 1111 1111", EntityKind::CreditCard),
    ("tel +33 6 12 34 56 78", EntityKind::Phone),
];

/// `text` with every ASCII digit written in the block starting at `zero`.
fn in_script(text: &str, zero: u32) -> String {
    text.chars()
        .map(|ch| match ch.to_digit(10) {
            Some(value) => char::from_u32(zero + value).expect("valid digit"),
            None => ch,
        })
        .collect()
}

fn kinds(registry: &Registry, text: &str) -> Vec<EntityKind> {
    let mut kinds: Vec<EntityKind> = registry.analyze(text).into_iter().map(|s| s.kind).collect();
    kinds.sort_by_key(|kind| format!("{kind:?}"));
    kinds
}

#[test]
fn newer_script_digits_are_detected_like_ascii() {
    let registry = Registry::new();
    for (ascii, kind) in SAMPLES {
        let expected = kinds(&registry, ascii);
        assert!(expected.contains(&kind), "{kind:?} not found in {ascii:?}");
        for zero in SCRIPT_ZEROS {
            let text = in_script(ascii, zero);
            assert_eq!(kinds(&registry, &text), expected, "U+{zero:X}: {text:?}");
        }
    }
}

#[test]
fn newer_script_digits_do_not_survive_masking() {
    let registry = Registry::new();
    for (ascii, _) in SAMPLES {
        for zero in SCRIPT_ZEROS {
            let text = in_script(ascii, zero);
            let spans = registry.analyze(&text);
            let mut anonymizer = Anonymizer::new([0x5au8; 32]);
            let masked = anonymizer.anonymize(&text, &spans).0;
            let digits: String = ascii.split_once(' ').expect("label").1.into();
            let written = in_script(&digits, zero);
            assert!(
                !masked.contains(&written),
                "U+{zero:X} survived: {masked:?}"
            );
        }
    }
}
