use super::masked;

/// ID-LABEL-1: `licence` is a label only when a number word follows it.
#[test]
fn a_licence_word_is_a_label_before_a_number_word_only() {
    for (text, value) in [
        ("licence number 12AB34567", "12AB34567"),
        ("Licence No. 12AB34567", "12AB34567"),
        ("License Number: 12AB34567", "12AB34567"),
        ("licence n°12AB34567", "n°12AB34567"),
        ("licence\nnumber: 72BD41385", "72BD41385"),
        ("Purpose: business\nLicence number: 72BD41385", "72BD41385"),
        ("Licence number: 99-99-99", "99-99-99"),
    ] {
        assert_eq!(masked(text), [value], "{text:?}");
    }
    for text in [
        "licence: 2024-10-01",
        "licence 12AB34567",
        "licence notes 12AB34567",
        "licence number is on file",
        "licence number: 2024-10-01",
        "licence no 01/10/2024",
        "the certificate license number 84730249",
        // Seal A round 1: two line breaks, a business word in the same
        // field, a real date in either order.
        "licence\n\nnumber: 72BD41385",
        "Purpose of the business licence number 84730249",
        "licence number: 31-12-99",
        "licence number: 12/31/2024",
        "licence number: 99-12-31",
    ] {
        assert!(masked(text).is_empty(), "{text:?}: {:?}", masked(text));
    }
}
/// ID-LABEL-2 round 1: `(` is decoration for an ID or a health label only.
/// Behind a secret label it is the first byte of the value.
#[test]
fn an_open_paren_is_decoration_for_a_wide_label_only() {
    for (text, value) in [
        (
            "driver_license_number (D37-4519-8820-41)",
            "D37-4519-8820-41",
        ),
        ("tax id (no1234)", "no1234"),
        ("api_key (smith-404135-zt7jh)", "(smith-404135-zt7jh"),
        ("api_key (smith\r\n404135-zt7jh", "(smith"),
        ("api_key\t(JQA028344)", "(JQA028344"),
        ("password (hunter22)", "(hunter22"),
    ] {
        assert!(
            masked(text).contains(&value),
            "{text:?}: {:?}",
            masked(text)
        );
    }
    // `[secret removed]` still guards a wide label's value; behind a secret
    // label the `(` is read with the token, exactly as on main.
    assert!(masked("driver_license_number ([secret removed])").is_empty());
    assert!(masked("passport ([secret removed])").is_empty());
    assert_eq!(masked("api_key ([secret removed])"), ["([secret"]);
    assert_eq!(masked("password ([secret removed])"), ["([secret"]);
}
