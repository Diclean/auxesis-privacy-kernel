//! Unit tests for the secret recognisers: the shared helpers, the pinned spans
//! of main, and the child modules by topic.

use super::*;

fn hits(text: &str) -> Vec<&str> {
    let mut spans: Vec<_> = SecretRecognizer::new()
        .analyze(text)
        .into_iter()
        .map(|span| (span.start, span.end))
        .collect();
    // `link_scan` may repeat a span of main's: the same bytes, one hit.
    spans.sort_unstable();
    spans.dedup();
    spans
        .into_iter()
        .map(|(start, end)| &text[start..end])
        .collect()
}

/// The text with every masked character left out.
fn clear_of(text: &str) -> String {
    let spans = SecretRecognizer::new().analyze(text);
    text.char_indices()
        .filter(|&(at, _)| !spans.iter().any(|span| span.start <= at && at < span.end))
        .map(|(_, ch)| ch)
        .collect()
}

/// Main's spans and `value_too_long` (2e85caf7) for the differential corpus: the
/// secrets tests' inputs, the K-SECRET-TAIL-2 inputs and 20 sentences with no
/// secret. Main's over-masks (`before`, `rules`, `again`) are kept as they are.
/// A text, main's spans of it, and main's `value_too_long`.
type Pinned = (&'static str, &'static [(usize, usize)], bool);
#[rustfmt::skip]
    const MAIN_SPANS: &[Pinned] = &[
        ("My password is correct horse battery staple", &[(15, 22), (22, 43)], false),
        ("Password for the portal is Tr0ub4dor and3 more words. Thanks", &[(27, 36), (36, 52)], false),
        ("My password is correct horse battery staple token=Tail9Token", &[(15, 22), (22, 60), (50, 60)], false),
        ("token=\"password is correct password\" is Outside9Secret", &[(6, 36), (26, 54), (40, 54)], false),
        ("token=\"password is correct\" pin is 4821", &[(6, 27), (26, 39), (35, 39)], false),
        ("password is the same as before: Sunflower#88 horse battery staple", &[(32, 44), (44, 65)], false),
        ("Your password is required", &[], false),
        ("my password is Tr0ubProse42", &[(15, 27)], false),
        ("mysql -pTr0ubCliP42", &[(8, 19)], false),
        ("api key: Q7vL2mX9pR4tY8wZ1nB6cD3fGhJkLmNp", &[(9, 41)], false),
        ("the wifi password is Xk9mP2q", &[(21, 28)], false),
        ("passwd Xk9mP2q", &[(7, 14)], false),
        ("**password**: Zq7Lm2Xr", &[(14, 22)], false),
        ("`password` is Zq7Lm2Xr", &[(14, 22)], false),
        ("\"password\" is Zq7Lm2Xr", &[(14, 22)], false),
        ("'api key': Zq7Lm2Xr", &[(11, 19)], false),
        ("__passwd__ Zq7Lm2Xr", &[(11, 19)], false),
        ("`token`: Zq7Lm2Xr", &[(9, 17)], false),
        ("**api_key**: Zq7Lm2Xr", &[(13, 21)], false),
        ("**Secret key:** Zq7Lm2Xr", &[(16, 24)], false),
        ("`token` is Zq7Lm2Xr", &[(11, 19)], false),
        ("“password” is Zq7Lm2Xr", &[(18, 26)], false),
        ("my “password” is Zq7Lm2Xr", &[(21, 29)], false),
        ("«password» is Zq7Lm2Xr", &[(16, 24)], false),
        ("password is Zq7*****", &[(12, 20)], false),
        ("my password is hunter2}}}", &[(15, 25)], false),
        ("__token__ is Zq7Lm2Xr", &[(13, 21)], false),
        ("`clientSecret` is Zq7Lm2Xr", &[(18, 26)], false),
        ("the `GITHUB_TOKEN` is Zq7Lm2Xr", &[(22, 30)], false),
        ("the `status` is Zq7Lm2Xr", &[], false),
        ("the password manager", &[], false),
        ("reset the password for Camille", &[], false),
        ("the api key field", &[], false),
        ("the `token` field", &[], false),
        ("pwd", &[], false),
        ("ssh -pTr0ubCliP42 host", &[], false),
        ("My **password** is correct horse battery staple", &[(19, 26)], false),
        ("My password is set to Tr0ub4dor horse battery staple", &[(22, 31)], false),
        ("Mon mot de passe est correct horse battery staple", &[], false),
        ("My password is set.", &[], false),
        ("password: **hunter2**", &[(10, 21)], false),
        ("mot de passe : correct horse battery staple", &[(15, 43)], false),
        ("Mot de passe : Tr0ub4dor", &[(15, 24)], false),
        ("mdp: Tr0ub4dor horse battery staple", &[(5, 35)], false),
        ("Mon mdp est Tr0ub4dor horse battery staple", &[], false),
        ("My `password` is correct horse battery staple, thanks", &[(17, 24)], false),
        ("**password** is Zq7Lm2Xr", &[(16, 24)], false),
        ("My password was changed to Tr0ub4dor horse battery staple. Bye", &[(27, 36)], false),
        ("password is set to \"Tr0ub4dor horse\" ok", &[(20, 35)], false),
        ("Le mot de passe du portail est correct horse battery staple", &[], false),
        ("**password** is pin is 4821", &[(23, 27)], false),
        ("My __password__ is correct horse battery staple", &[(19, 26)], false),
        ("My **password** is set to Tr0ub4dor horse battery staple", &[], false),
        ("Mon mot-de-passe est Tr0ub4dor horse battery staple", &[], false),
        ("Mon **mot de passe** est Tr0ub4dor horse battery staple", &[], false),
        // KV02-SECRETS-5: main's htpasswd and SSWS spans at de810da (#101).
        ("htpasswd -b site.db \"alice smith\" correcthorse", &[(27, 33)], false),
        ("htpasswd -nb \"alice smith\" correcthorse", &[(20, 26), (27, 39)], false),
        ("htpasswd -b site.db \"alice smith\" then restart", &[(27, 33)], false),
        ("htpasswd -b users.htpasswd alice Hunter22ht", &[(33, 43)], false),
        ("htpasswd -nb alice Hunter22ht2", &[(19, 30)], false),
        ("htpasswd -nbBC 10 bob Hunter22ht3 >> users.htpasswd", &[(22, 33)], false),
        ("htpasswd -b site.db alice \"my pass word\"", &[(26, 40)], false),
        ("htpasswd -b \"/srv/my site/.htpasswd\" alice S3cretPass", &[(37, 42), (43, 53)], false),
        ("htpasswd -b site.db 'alice smith' S3cretPass", &[(27, 33), (34, 44)], false),
        ("SSWS token\nabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP", &[(11, 53)], false),
        ("Our ssws ImplementationGuide", &[(9, 28)], false),
        ("The password policy is set to strict mode for the team.", &[], false),
        ("Mon mot de passe est oublié.", &[], false),
        ("Le mot de passe est trop court.", &[], false),
        ("Mon mot de passe est incorrect, merci de le changer.", &[], false),
        ("Please reset your password before Monday.", &[(27, 33)], false),
        ("The password is required to log in.", &[], false),
        ("We changed the password rules last week.", &[(24, 29)], false),
        ("Your password must have eight characters.", &[], false),
        ("I forgot my password again, sorry.", &[(21, 26)], false),
        ("The **password** field is empty.", &[], false),
        ("The password reset link expired.", &[], false),
        ("Password strength: Strong", &[(9, 18)], false),
        ("The api key field is empty.", &[], false),
        ("Mot de passe oublié ?", &[], false),
        ("Le mot de passe a été changé hier.", &[], false),
        ("Où est mon mot de passe ?", &[], false),
        ("The pass to the museum is on the table.", &[], false),
        ("Our team code review is on Friday.", &[], false),
        ("The token of thanks was a card.", &[], false),
        ("Merci pour le mot de passe, il marche.", &[], false),
    ];

#[test]
fn every_span_of_main_is_still_produced() {
    for &(text, main, too_long) in MAIN_SPANS {
        let new: Vec<(usize, usize)> = SecretRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| (span.start, span.end))
            .collect();
        for span in main {
            assert!(new.contains(span), "{text}: lost {span:?}, now {new:?}");
        }
        assert_eq!(value_too_long(text), too_long, "{text}");
    }
    // The sentences with no secret gain no span (the last 20 rows).
    for &(text, main, _) in &MAIN_SPANS[MAIN_SPANS.len() - 20..] {
        let mut new: Vec<(usize, usize)> = SecretRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| (span.start, span.end))
            .collect();
        new.sort_unstable();
        let over = OVER_MASKS.iter().find(|row| row.0 == text);
        assert_eq!(new, over.map_or(main, |row| row.1), "{text}");
    }
}

/// K-SECRET-TAIL-4 over-masks: the no-secret rows that now mask the words
    /// after their link, with main's spans kept.
    #[rustfmt::skip]
    const OVER_MASKS: &[(&str, &[(usize, usize)])] = &[
        ("Mon mot de passe est oublié.", &[(21, 29)]),
        ("Le mot de passe est trop court.", &[(20, 31)]),
        ("Mon mot de passe est incorrect, merci de le changer.", &[(21, 52)]),
        ("The password is required to log in.", &[(16, 35)]),
        ("Password strength: Strong", &[(9, 18), (19, 25)]),
    ];

#[test]
fn declared_kind_and_name() {
    let recognizer = SecretRecognizer::new();
    assert_eq!(recognizer.kinds(), &[EntityKind::Secret]);
    assert_eq!(recognizer.name(), "secrets");
}

mod prose;
mod shapes;
