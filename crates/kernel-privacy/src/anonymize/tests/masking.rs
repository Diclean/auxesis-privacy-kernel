//! Masking, escaping, and round-trip tests.

use super::*;

#[test]
fn token_is_stable_within_a_session() {
    let mut anonymizer = Anonymizer::new([7u8; 32]);
    let text = "ecrivez a a@example.com puis a a@example.com";
    let first = text.find("a@example.com").unwrap();
    let second = text.rfind("a@example.com").unwrap();
    let spans = vec![
        span(EntityKind::Email, first, first + "a@example.com".len()),
        span(EntityKind::Email, second, second + "a@example.com".len()),
    ];
    let (masked, pairs) = anonymizer.anonymize(text, &spans);
    assert_eq!(pairs.len(), 1);
    assert!(pairs[0].0.starts_with("EMAIL_"));
    assert_eq!(pairs[0].1, "a@example.com");
    assert_eq!(masked.matches(&pairs[0].0).count(), 2);
    assert_eq!(masked.matches(PLACEHOLDER_OPEN).count(), 2);
    assert!(!masked.contains("a@example.com"));
}
#[test]
fn two_keys_give_different_tokens() {
    let value = "a@example.com";
    let text = format!("mail {value}");
    let start = text.find(value).unwrap();
    let spans = vec![span(EntityKind::Email, start, start + value.len())];
    let mut one = Anonymizer::new([1u8; 32]);
    let mut two = Anonymizer::new([2u8; 32]);
    let (first_masked, first_pairs) = one.anonymize(&text, &spans);
    let (second_masked, second_pairs) = two.anonymize(&text, &spans);
    assert_eq!(first_pairs.len(), 1);
    assert_eq!(second_pairs.len(), 1);
    assert_ne!(first_pairs[0].0, second_pairs[0].0);
    assert_ne!(first_masked, second_masked);
    assert_ne!(
        one.digest(EntityKind::Email, value),
        two.digest(EntityKind::Email, value)
    );
}
#[test]
fn distinct_values_get_distinct_tokens() {
    let mut anonymizer = Anonymizer::new([3u8; 32]);
    let (first, _) = anonymizer.token_for(EntityKind::Email, "a@example.com");
    let (second, _) = anonymizer.token_for(EntityKind::Email, "b@example.com");
    assert_ne!(first, second);
    assert_eq!(anonymizer.len(), 2);
}
#[test]
fn kinds_are_part_of_the_digest_input() {
    let anonymizer = Anonymizer::new([3u8; 32]);
    assert_ne!(
        anonymizer.digest(EntityKind::Phone, "12345"),
        anonymizer.digest(EntityKind::FrSiren, "12345")
    );
}
#[test]
fn shared_token_restores_each_surface_form() {
    let mut anonymizer = Anonymizer::new([0x55u8; 32]);
    let text = "tel 0612345678 puis 06 12 34 56 78 fin";
    let first = text.find("0612345678").unwrap();
    let second = text.find("06 12 34 56 78").unwrap();
    let spans = vec![
        span(EntityKind::Phone, first, first + "0612345678".len()),
        span(EntityKind::Phone, second, second + "06 12 34 56 78".len()),
    ];
    let (masked, pairs) = anonymizer.anonymize(text, &spans);
    // Same normalised value: one distinct entry, two occurrences.
    assert_eq!(pairs.len(), 1, "same normalised value must share a token");
    let token = pairs[0].0.clone();
    assert_eq!(masked.matches(&token).count(), 2);
    assert_eq!(restore_keep(&masked, &pairs), text);
}
#[test]
fn tokens_key_on_the_exact_spelling_and_restore_it_byte_for_byte() {
    let mut anonymizer = Anonymizer::new([0x3Cu8; 32]);
    let text = "Le et le, GROSS et Groß.";
    let spans: Vec<Span> = ["Le", "le", "GROSS", "Groß"]
        .iter()
        .map(|word| {
            let start = text.find(word).expect("word in text");
            span(EntityKind::Person, start, start + word.len())
        })
        .collect();
    let (masked, pairs) = anonymizer.anonymize(text, &spans);
    assert_eq!(pairs.len(), 4, "each spelling keys its own token");
    assert_eq!(restore_keep(&masked, &pairs), text);
}
#[test]
fn restore_round_trips_exact_text_including_plus() {
    let mut anonymizer = Anonymizer::new([4u8; 32]);
    let text = "tel +33 6 12 34 56 78 et mail a@b.co fin";
    let phone = text.find("+33").unwrap();
    let mail = text.find("a@b.co").unwrap();
    let spans = vec![
        span(EntityKind::Phone, phone, phone + "+33 6 12 34 56 78".len()),
        span(EntityKind::Email, mail, mail + "a@b.co".len()),
    ];
    let (masked, pairs) = anonymizer.anonymize(text, &spans);
    assert_eq!(pairs.len(), 2);
    assert!(pairs
        .iter()
        .any(|(_, original)| original == "+33 6 12 34 56 78"));
    assert_eq!(restore_keep(&masked, &pairs), text);
}
#[test]
fn masked_text_keeps_surrounding_text_and_is_ordered() {
    let mut anonymizer = Anonymizer::new([4u8; 32]);
    let text = "tel 0612345678 et mail a@b.co fin";
    let phone_start = text.find("0612345678").unwrap();
    let mail_start = text.find("a@b.co").unwrap();
    let spans = vec![
        span(EntityKind::Email, mail_start, mail_start + 6),
        span(EntityKind::Phone, phone_start, phone_start + 10),
    ];
    let (masked, pairs) = anonymizer.anonymize(text, &spans);
    assert_eq!(pairs.len(), 2);
    assert!(pairs[0].0.starts_with("PHONE_"));
    assert!(pairs[1].0.starts_with("EMAIL_"));
    assert_eq!(
        masked,
        format!("tel ⟦{}⟧ et mail ⟦{}⟧ fin", pairs[0].0, pairs[1].0)
    );
}
#[test]
fn literal_delimiters_are_escaped_and_restore_is_exact() {
    let mut anonymizer = Anonymizer::new([0x77u8; 32]);
    let text = "avant ⟦ et ⟧ puis 0612345678 fin";
    let start = text.find("0612345678").unwrap();
    let spans = vec![span(EntityKind::Phone, start, start + 10)];
    let (masked, pairs) = anonymizer.anonymize(text, &spans);
    // Only the literal opener is doubled; the closer is plain clear text.
    assert_eq!(masked.matches(PLACEHOLDER_OPEN).count(), 3);
    assert!(masked.starts_with("avant ⟦⟦ et ⟧ puis ⟦PHONE_"));
    assert_eq!(restore_keep(&masked, &pairs), text);
}
#[test]
fn a_typed_placeholder_is_text_never_a_token() {
    let mut anonymizer = Anonymizer::new([0x7Du8; 32]);
    let mail = "a@example.com";
    let base = format!("mail {mail}");
    let start = base.find(mail).unwrap();
    let spans = [span(EntityKind::Email, start, start + mail.len())];
    let (_, first) = anonymizer.anonymize(&base, &spans);
    let token = first[0].0.clone();
    // A real token of this session, typed by the user after the real value.
    let text = format!("mail {mail} faux ⟦{token}⟧");
    let start = text.find(mail).unwrap();
    let spans = [span(EntityKind::Email, start, start + mail.len())];
    let (masked, pairs) = anonymizer.anonymize(&text, &spans);
    let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
    assert_eq!(report.text, text);
    assert!(report.is_clean(), "the typed look-alike must stay text");
}
#[test]
fn backslashes_and_escape_lookalikes_round_trip() {
    let mut anonymizer = Anonymizer::new([0x78u8; 32]);
    let text = r"a \ b \\ c \u27E6 d 〚e〛 ⟧";
    let (masked, pairs) = anonymizer.anonymize(text, &[]);
    // Only a literal opener is rewritten: backslashes and look-alikes pass through.
    assert_eq!(masked, text);
    assert_eq!(restore_keep(&masked, &pairs), text);
}
#[test]
fn undelimited_token_like_text_is_never_touched() {
    let mut anonymizer = Anonymizer::new([0x7Cu8; 32]);
    let (token, _) = anonymizer.token_for(EntityKind::Phone, "0612345678");
    let text = format!("{token} avant 0612345678 apres {token}");
    let start = text.find("0612345678").unwrap();
    let spans = vec![span(EntityKind::Phone, start, start + 10)];
    let (masked, pairs) = anonymizer.anonymize(&text, &spans);
    assert!(masked.contains(&format!("{token} avant")));
    let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
    assert_eq!(report.text, text);
    assert!(report.is_clean());
}
