use super::masked;

#[test]
fn a_value_after_its_label_is_masked() {
    for (text, value) in [
        ("the password might be G9$rP2zT@qWk", "G9$rP2zT@qWk"),
        ("the password, Sunflower@2025, opens it", "Sunflower@2025"),
        ("I changed my pin to 619036 yesterday", "619036"),
        ("**api\\_key**: Zq9Lm2Xv8Rt4Wp7N", "Zq9Lm2Xv8Rt4Wp7N"),
        ("password: 'red horse' ok", "red horse"),
        ("Patient MRN 448812 was admitted.", "448812"),
        ("Personalausweis-Nr. L01X00T47", "L01X00T47"),
        ("| Tax ID   |   98-7654321 |", "98-7654321"),
        ("CNI : 1234 5678 9012 ok", "1234 5678 9012"),
        ("Her blood type is A positive.", "A positive"),
        ("Blood group: AB+", "AB+"),
        ("Blood type: O", "O"),
        ("The patient's blood type is AB-.", "AB-"),
        ("Blood group: AB Rh-", "AB Rh-"),
        ("a blood type of O+ and", "O+"),
        ("mon groupe sanguin c'est A- en fait", "A-"),
        ("medical record number for this donor is 0008811", "0008811"),
        (
            "member ID: QHX81402277 from the health insurer",
            "QHX81402277",
        ),
        ("Numéro de dossier médical : DM-2024-77812", "DM-2024-77812"),
        ("血型：A型Rh阴性", "A型Rh阴性"),
        ("密码是abc12345", "abc12345"),
        ("csrftoken=Ab12Cd34Ef; Path=/", "Ab12Cd34Ef"),
        ("\"password\": \"hunter22\"", "hunter22"),
    ] {
        assert!(
            masked(text).contains(&value),
            "{text:?}: {:?}",
            masked(text)
        );
    }
}
#[test]
fn a_label_without_a_value_masks_nothing() {
    for text in [
        "spinning 12345678",
        "health plan 2024",
        "password: ⟦SECRET_0123456789AB⟧ and pin [secret removed]",
        "passport\n\n\nAB1234567",
        "<input type=\"password\" id=\"pin\" name=\"pin\" required>",
        "<title>PIN Entry</title> Select 'Change PIN'. 4. Enter",
        "portal/pin-login](https://x.org/pin-login)",
        "| Authentication | Session | https://ico.org.uk |",
        "the certificate license number 84730249",
        "gym member ID 44120098",
        "His health is fine; gym member ID 55120934.",
        "loyalty member number 7712-0093",
        "medical record number for each patient is required",
        "the medical record number for 2024",
        "the password of user123 expired",
        // ID-LABEL-2: a label, and no value behind it.
        "Numéro de permis de conduire à renouveler",
        "N° de permis : à préciser",
        "permis n°",
        "driver_license_number is empty",
        "driver license number (to be confirmed)",
        "passport no: E 1234",
        "passport no: E 12345 6789",
        "passport no: EXY 1234 5678",
        "N° de permis n° rien",
    ] {
        assert!(masked(text).is_empty(), "{text:?}: {:?}", masked(text));
    }
}
#[test]
fn utf8_edges_never_panic() {
    for text in [
        "pin ⟦",
        "密码",
        "password: é",
        "blood type: O\u{301}",
        "MRN 12\u{0}",
        "; path=",
    ] {
        let _ = masked(text);
    }
    let long = format!("password: {}", "é1".repeat(300));
    assert!(!masked(&long).is_empty());
}
