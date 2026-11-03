use super::masked;

/// ID-LABEL-2: the label forms main read one value and left the next in
/// clear.
#[test]
fn a_glued_number_sign_a_spaced_passport_and_a_paren_key_are_read() {
    for (text, value) in [
        ("Numéro de permis de conduire : 12AB34567", "12AB34567"),
        ("N° de permis de conduire : 12AB34567", "12AB34567"),
        ("NUMERO DE PERMIS DE CONDUIRE : 12AB34567", "12AB34567"),
        ("Numéro de permis de conduire:\n12AB34567", "12AB34567"),
        ("numéro de permis de conduire n°12AB34567", "n°12AB34567"),
        ("N° de permis n°12AB34567", "n°12AB34567"),
        ("numéro de permis n°071234567890", "n°071234567890"),
        ("护照号：E 1234 5678", "E 1234 5678"),
        ("passport no: EA 1234 5678", "EA 1234 5678"),
        ("passport number is E 1234 5678", "E 1234 5678"),
        (
            "driver_license_number (D37-4519-8820-41)",
            "D37-4519-8820-41",
        ),
        (
            "{\"driving_license_number\": \"(D37-4519-8820-41)\"}",
            "D37-4519-8820-41",
        ),
        (
            "driver licence number (MORGA-753116-SM9IJ)",
            "MORGA-753116-SM9IJ",
        ),
    ] {
        assert!(
            masked(text).contains(&value),
            "{text:?}: {:?}",
            masked(text)
        );
    }
}
/// ID-LABEL-2 round 1: a glued sign's own letters are alphanumerics of the
/// value, so `no1234` reads exactly as it reads on main.
#[test]
fn a_glued_signs_letters_count_toward_the_minimum() {
    for (text, value) in [
        ("tax id no1234", "no1234"),
        ("passport NO123", "NO123"),
        ("medical record number no123", "no123"),
        ("member ID no123 at the health insurer", "no123"),
        ("NHS number: no12", "no12"),
        ("Tax ID: no12", ""),
    ] {
        let spans: Vec<_> = masked(text);
        if value.is_empty() {
            assert!(spans.is_empty(), "{text:?}: {spans:?}");
        } else {
            assert!(spans.contains(&value), "{text:?}: {spans:?}");
        }
    }
    // A sign main cannot read past keeps the head's own reading, and its
    // `n` counts toward the minimum length too.
    assert_eq!(masked("N° de permis n°1234"), ["n°1234"]);
    assert_eq!(masked("N° de permis n°123"), Vec::<&str>::new());
    assert_eq!(masked("tax id nothing12"), ["nothing12"]);
}
/// ID-LABEL-2 round 1: a spaced CN passport is read behind a passport label
/// only.
#[test]
fn a_spaced_passport_needs_a_passport_label() {
    for (text, value) in [
        ("passport no: E 1234 5678", "E 1234 5678"),
        ("护照号：E 1234 5678", "E 1234 5678"),
        ("tax id: E 1234 5678", ""),
        ("CNI: E 1234 5678", ""),
        ("driver licence number: E 1234 5678", ""),
    ] {
        let spans = masked(text);
        if value.is_empty() {
            assert!(spans.is_empty(), "{text:?}: {spans:?}");
        } else {
            assert!(spans.contains(&value), "{text:?}: {spans:?}");
        }
    }
}
