//! Values wrapped across lines stay one value in the recognisers.

#[test]
fn a_wrapped_iban_is_still_found() {
    use crate::recognizer::Recognizer;
    use crate::recognizers::iban::IbanRecognizer;

    // FAKE: the checksum-valid specimen FR IBAN used across the tests.
    let text = "voici FR76 3000 6000 0112 3456\n7890 189 merci";
    let spans = IbanRecognizer::new().analyze(text);
    assert_eq!(spans.len(), 1, "{spans:?}");
    assert_eq!(
        &text[spans[0].start..spans[0].end],
        "FR76 3000 6000 0112 3456\n7890 189"
    );
}

#[test]
fn an_iban_broken_with_crlf_and_spaces_is_still_found() {
    use crate::recognizer::Recognizer;
    use crate::recognizers::iban::IbanRecognizer;

    // FAKE: the same specimen, broken with CRLF plus indentation.
    let text = "FR76 3000 6000 0112\r\n   3456 7890 189";
    let spans = IbanRecognizer::new().analyze(text);
    assert_eq!(spans.len(), 1, "{spans:?}");
    assert_eq!(&text[spans[0].start..spans[0].end], text);
}

#[test]
fn a_wrapped_phone_is_still_found() {
    use crate::recognizer::Recognizer;
    use crate::recognizers::phone::PhoneRecognizer;

    // FAKE: a number in the 555 fiction range, wrapped after the area code.
    let text = "appelle +1 (202)\r\n555-0142 demain";
    let spans = PhoneRecognizer::new().analyze(text);
    assert_eq!(spans.len(), 1, "{spans:?}");
    let found = &text[spans[0].start..spans[0].end];
    assert!(
        found.contains("\r\n") && found.ends_with("0142"),
        "{found:?}"
    );
}

#[test]
fn an_iban_split_by_an_invisible_run_over_the_cap_does_not_merge() {
    use crate::recognizer::Recognizer;
    use crate::recognizers::iban::IbanRecognizer;

    // FAKE: the specimen FR IBAN, cut by nine zero-width spaces.
    let text = format!("FR76 3000 6000 0112 3456{}7890 189", "\u{200B}".repeat(9));
    assert!(IbanRecognizer::new().analyze(&text).is_empty());
}

#[test]
fn an_iban_split_by_a_blank_paragraph_does_not_merge() {
    use crate::recognizer::Recognizer;
    use crate::recognizers::iban::IbanRecognizer;

    // FAKE: the specimen FR IBAN, cut by a blank paragraph. Neither half is
    // an IBAN, and no span may bridge the two.
    let text = "FR76 3000 6000 0112 3456\n\n\n7890 189";
    assert!(IbanRecognizer::new().analyze(text).is_empty());
}

#[test]
fn two_numbers_split_by_a_blank_paragraph_do_not_merge() {
    use crate::recognizer::Recognizer;
    use crate::recognizers::phone::PhoneRecognizer;

    // FAKE: two numbers in the 555 fiction range, a blank paragraph apart.
    let text = "+1 (202) 555-0142\n\n\n+1 (202) 555-0199";
    let spans = PhoneRecognizer::new().analyze(text);
    assert!(!spans.is_empty(), "{spans:?}");
    for span in spans {
        let found = &text[span.start..span.end];
        assert!(!found.contains('\n'), "{found:?}");
    }
}

#[test]
fn masking_never_spans_past_the_identifier_and_its_folds() {
    use crate::recognizer::Recognizer;
    use crate::recognizers::iban::IbanRecognizer;

    // FAKE: a wrapped specimen IBAN followed by a long blank region.
    let wrapped = "FR76 3000 6000 0112 3456\n7890 189";
    let text = format!("{wrapped}{}", " ".repeat(10_000));
    let spans = IbanRecognizer::new().analyze(&text);
    assert_eq!(spans.len(), 1, "{spans:?}");
    assert_eq!(&text[spans[0].start..spans[0].end], wrapped);
}
