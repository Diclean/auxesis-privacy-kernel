use super::hidden;

#[test]
fn a_value_after_a_prose_link_is_found() {
    let value = format!("Wq5{}", "$wDf8n");
    let text = format!("I changed the admin password on the NAS to {value} today.");
    assert_eq!(hidden(&text), [value.as_str()]);
    assert_eq!(
        hidden("Please enter your PIN, which is 552190, in the box."),
        ["552190"]
    );
}

#[test]
fn prose_after_a_link_stays_clear() {
    for text in [
        "the password is required",
        "set it to default",
        "The key, in short, is patience.",
        "password-protected files are opened with care",
        "theme=dark; Path=/",
    ] {
        assert!(hidden(text).is_empty(), "{text}");
    }
}
