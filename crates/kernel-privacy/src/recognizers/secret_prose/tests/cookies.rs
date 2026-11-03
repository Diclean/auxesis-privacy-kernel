use super::hidden;

#[test]
fn a_cookie_takes_its_attributes() {
    let value = format!("sid={}", "Vt9Rw4Zp8Kx3Nb45");
    let text = format!("the http cookie {value}; Path=/; HttpOnly in the call");
    assert_eq!(
        hidden(&text),
        [format!("{value}; Path=/; HttpOnly").as_str()]
    );
}
