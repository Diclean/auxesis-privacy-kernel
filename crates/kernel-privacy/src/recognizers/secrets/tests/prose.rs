//! The prose, decorated and French secret rules, and their linear-time bounds.

use super::*;

mod timing {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/timing.rs"
    ));
}

#[test]
fn a_multi_word_password_is_masked_to_its_clause_end() {
    let masked = |text: &str| {
        let mut kept: Vec<(usize, usize)> = SecretRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| (span.start, span.end))
            .collect();
        kept.sort_unstable();
        text.char_indices()
            .filter(|&(at, _)| !kept.iter().any(|&(start, end)| start <= at && at < end))
            .map(|(_, ch)| ch)
            .collect::<String>()
    };
    for (text, clear) in [
        (
            "My password is correct horse battery staple",
            "My password is ",
        ),
        (
            "Password for the portal is Tr0ub4dor and3 more words. Thanks",
            "Password for the portal is ",
        ),
        // Seal r1 of #142: a key-value later on the line, a long tail.
        (
            "My password is correct horse battery staple token=Tail9Token",
            "My password is ",
        ),
        // Seal r2 of #142: main's later values all stay masked.
        (
            "token=\"password is correct password\" is Outside9Secret",
            "",
        ),
        ("token=\"password is correct\" pin is 4821", ""),
    ] {
        let out = masked(text);
        for word in [
            "horse",
            "staple",
            "Tail9Token",
            "more",
            "Outside9Secret",
            "4821",
        ] {
            assert!(
                !out.contains(word),
                "{word} left clear in {text:?}: {out:?}"
            );
        }
        if !clear.is_empty() {
            assert_eq!(out, clear, "{text}");
        }
    }
    let colon = "password is the same as before: Sunflower#88 horse battery staple";
    assert!(!masked(colon).contains("horse"), "{}", masked(colon));
    let colon_long = format!("{colon} {}TAIL", "word ".repeat(300));
    assert!(value_too_long(&colon_long));
    let long = format!("password is {}TAIL", "word ".repeat(26));
    assert!(!masked(&long).contains("TAIL"));
    assert!(value_too_long(&format!(
        "password is correct pin is A1{}",
        "x".repeat(1024)
    )));
    // K-SECRET-TAIL-4 over-mask: a value runs to its paragraph end.
    assert_eq!(hits("Your password is required"), vec!["required"]);
}

/// A multi-word password and what is masked of it: main masked only its first word,
    /// or (French) nothing (seals r1 of #142 and #148).
    #[rustfmt::skip]
    const DECORATED_VALUES: &[(&str, &str)] = &[
        ("My **password** is correct horse battery staple", "correct horse battery staple"),
        ("My password is set to Tr0ub4dor horse battery staple", "Tr0ub4dor horse battery staple"),
        ("Mon mot de passe est correct horse battery staple", "correct horse battery staple"),
        ("My `password` is correct horse battery staple, thanks", "correct horse battery staple"),
        ("My password was changed to Tr0ub4dor horse battery staple. Bye", "Tr0ub4dor horse battery staple"),
        ("Le mot de passe du portail est correct horse battery staple", "correct horse battery staple"),
        ("mot de passe : correct horse battery staple", "correct horse battery staple"),
        // The asterisks are masked with the value, as main masks them.
        ("password: **hunter2**", "**hunter2**"),
        // A quoted value ends at its quote, as on main.
        ("password is set to \"Tr0ub4dor horse\" ok", "Tr0ub4dor horse"),
        ("My __password__ is correct horse battery staple", "correct horse battery staple"),
        ("My **password** is set to Tr0ub4dor horse battery staple", "Tr0ub4dor horse battery staple"),
        ("Mon mot-de-passe est Tr0ub4dor horse battery staple", "Tr0ub4dor horse battery staple"),
        ("Mon **mot de passe** est Tr0ub4dor horse battery staple", "Tr0ub4dor horse battery staple"),
        // A stopword glued to more is a value.
        ("Mon mot de passe est trop2024!", "trop2024!"),
        ("My **password** is the same as before: Sunflower#88 horse", "Sunflower#88 horse"),
    ];

#[test]
fn every_key_decoration_and_link_masks_the_whole_value() {
    let mut texts: Vec<(String, &str)> = DECORATED_VALUES
        .iter()
        .map(|&(text, value)| (text.to_owned(), value))
        .collect();
    let english = ["password", "Password", "PASSWORD", "pwd"].map(|key| (key, "My", true));
    let french =
        ["mot de passe", "mot-de-passe", "MOT DE PASSE", "mdp"].map(|key| (key, "Mon", false));
    for (key, lead, is_english) in english.into_iter().chain(french) {
        let links: &[&str] = if is_english {
            &[" is", " is set to", " was set to", " is now", ":"]
        } else {
            &[" est", " est maintenant", " :"]
        };
        for marks in ["", "**", "__", "`", "*"] {
            for link in links {
                let text =
                    format!("{lead} {marks}{key}{marks}{link} Tr0ub4dor horse battery staple");
                texts.push((text, "Tr0ub4dor horse battery staple"));
            }
        }
    }
    assert_eq!(texts.len(), DECORATED_VALUES.len() + 160);
    let wrong: Vec<_> = texts
        .iter()
        // K-SECRET-TAIL-4: the value runs to the text end, so what stays clear is
        // a head of the text that ends before the value.
        .filter(|(text, value)| {
            let clear = clear_of(text);
            !text.starts_with(&clear) || text.find(value).is_none_or(|at| clear.len() > at)
        })
        .map(|(text, _)| (text, clear_of(text)))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} of {} leak: {wrong:#?}",
        wrong.len(),
        texts.len()
    );
    // Decorated sentences with no secret keep their pinned spans.
    for &(text, pinned) in DECORATED_NO_SECRET {
        let mut new: Vec<(usize, usize)> = SecretRecognizer::new()
            .analyze(text)
            .iter()
            .map(|span| (span.start, span.end))
            .collect();
        new.sort_unstable();
        assert_eq!(new, pinned, "{text}");
    }
    // A long value or tail of this reading is masked whole, never refused:
    // main admitted these texts, and no byte of the secret is left clear.
    for long in [
        format!("My **password** is correct {}TAIL", "word ".repeat(300)),
        format!("Mon mdp est {}", "a".repeat(1025)),
    ] {
        assert!(!value_too_long(&long), "{long}");
        let start = long.find(" is ").map_or(12, |at| at + 4);
        let masked: usize = hits(&long).iter().map(|hit| hit.len()).sum();
        assert!(masked >= long.len() - start, "{long}");
    }
}

/// Accepted over-masks: after `mot de passe est`, any word that is not
/// a stopword is read as the value, so a sentence about a password loses a few
/// words to a mask. Secrets fail closed; these texts still pass the gate.
#[test]
fn a_french_sentence_about_a_password_is_over_masked_but_admitted() {
    for (text, pinned) in [
        (
            "Mon mot de passe est facile à retenir.",
            vec![(21, 27), (21, 39), (27, 38)],
        ),
        (
            "Le mot de passe est difficile à mémoriser.",
            vec![(20, 29), (20, 44), (29, 43)],
        ),
        (
            "Le mot de passe est secret et personnel.",
            vec![(20, 26), (20, 40), (26, 39)],
        ),
        (
            "Le mdp est utilisé pour se connecter.",
            vec![(11, 19), (11, 38), (19, 37)],
        ),
    ] {
        let mut spans: Vec<(usize, usize)> = SecretRecognizer::new()
            .analyze(text)
            .iter()
            .map(|span| (span.start, span.end))
            .collect();
        spans.sort_unstable();
        assert_eq!(spans, pinned, "{text}");
        assert!(!value_too_long(text), "{text}");
    }
}

/// Decorated sentences with no secret and their spans; an over-mask says why.
    #[rustfmt::skip]
    const DECORATED_NO_SECRET: &[(&str, &[(usize, usize)])] = &[
        ("The **password** policy is strict.", &[]),
        ("Le **mot de passe** doit être changé.", &[]),
        // Main's over-mask: its key rule reads `__required__` as a value.
        ("Your password is __required__.", &[(17, 29), (17, 30)]),
        ("The `password` field is required.", &[]),
        // Main's over-mask, the same: `*incorrect*`.
        ("Your **password** is *incorrect*.", &[(21, 32), (21, 33)]),
        ("Le *mot-de-passe* est **obligatoire**.", &[(22, 38)]),
        // Main's over-mask: its key rule masks the word after `pwd`.
        ("The __pwd__ command prints the folder.", &[(12, 19)]),
        // Main's over-mask: `**Password reset**` is a decorated secret name.
        ("**Password reset** is done.", &[(22, 26)]),
        ("Mon `mdp` est ~~oublié~~.", &[(14, 26)]),
        ("The ~~password~~ hint is in the vault.", &[]),
        ("My password is set.", &[(15, 19)]),
        ("**password** is pin is 4821", &[(16, 27), (23, 27)]),
    ];

#[test]
    #[rustfmt::skip]
    fn a_non_ascii_character_after_a_cue_never_splits_a_character() {
        let keys = ["password", "**password**", "mot de passe", "mdp", "password is set to"];
        let more = ["mot-de-passe est", "**password** is", "__pwd__:", "password is"];
        for key in keys.into_iter().chain(more) {
            for after in ["é", "😀", "密码", " é", " est é", " is 😀x", "é horse", " 😀😀😀😀 é. x", "\u{301}"] {
                let text = format!("{key}{after}{after} tail");
                for span in SecretRecognizer::new().analyze(&text) {
                    assert!(text.is_char_boundary(span.start) && text.is_char_boundary(span.end), "{text:?}: {span:?}");
                }
                let _ = value_too_long(&text);
            }
        }
    }

#[test]
fn a_prose_key_masks_the_next_word() {
    assert_eq!(hits("my password is Tr0ubProse42"), vec!["Tr0ubProse42"]);
    assert_eq!(hits("mysql -pTr0ubCliP42"), vec!["Tr0ubCliP42"]);
    assert_eq!(
        hits("api key: Q7vL2mX9pR4tY8wZ1nB6cD3fGhJkLmNp"),
        vec!["Q7vL2mX9pR4tY8wZ1nB6cD3fGhJkLmNp"]
    );
    assert_eq!(hits("the wifi password is Xk9mP2q"), vec!["Xk9mP2q"]);
    assert_eq!(hits("passwd Xk9mP2q"), vec!["Xk9mP2q"]);
}

#[test]
fn a_decorated_prose_key_masks_the_next_word() {
    assert_eq!(hits("**password**: Zq7Lm2Xr"), vec!["Zq7Lm2Xr"]);
    assert_eq!(hits("`password` is Zq7Lm2Xr"), vec!["Zq7Lm2Xr"]);
    assert_eq!(hits("\"password\" is Zq7Lm2Xr"), vec!["Zq7Lm2Xr"]);
    assert_eq!(hits("'api key': Zq7Lm2Xr"), vec!["Zq7Lm2Xr"]);
    assert_eq!(hits("__passwd__ Zq7Lm2Xr"), vec!["Zq7Lm2Xr"]);
}

#[test]
fn any_decorated_or_curly_quoted_key_masks_its_value() {
    // security-review B r4: Markdown, backtick and curly-quote marks around a key.
    for text in [
        "`token`: Zq7Lm2Xr",
        "`secret`: Zq7Lm2Xr",
        "`API_KEY`: Zq7Lm2Xr",
        "`OPENAI_API_KEY`: Zq7Lm2Xr",
        "**api_key**: Zq7Lm2Xr",
        "**client_secret**: Zq7Lm2Xr",
        "*Token*: Zq7Lm2Xr",
        "**Token**: Zq7Lm2Xr",
        "**Secret**: Zq7Lm2Xr",
        "**Pass**: Zq7Lm2Xr",
        "**Secret key:** Zq7Lm2Xr",
        "**Private key:** Zq7Lm2Xr",
        "**Access key:** Zq7Lm2Xr",
        "`token` is Zq7Lm2Xr",
        "\"token\" is Zq7Lm2Xr",
        "\u{201c}password\u{201d} is Zq7Lm2Xr",
        "\u{2018}password\u{2019} is Zq7Lm2Xr",
        "\u{201c}password\u{201d}: Zq7Lm2Xr",
        "{\u{201c}password\u{201d}: \u{201c}Zq7Lm2Xr\u{201d}}",
        "my \u{201c}password\u{201d} is Zq7Lm2Xr",
        "\u{201c}token\u{201d}: Zq7Lm2Xr",
        "\u{201c}api key\u{201d} is Zq7Lm2Xr",
        "\u{ab}password\u{bb} is Zq7Lm2Xr",
    ] {
        let found = hits(text);
        assert!(
            found.iter().any(|hit| hit.contains("Zq7Lm2Xr")),
            "{text} leaked: {found:?}"
        );
    }
    // Still clear: a decorated key with no value, and plain prose.
    assert!(hits("the `token` field").is_empty());
    assert!(hits("a \u{201c}secret\u{201d} recipe").is_empty());
}

#[test]
fn a_value_ending_in_marks_is_masked_whole() {
    // K15 seal r1: the marks trimmed to read a value are part of the secret.
    assert_eq!(hits("password is Zq7*****"), vec!["Zq7*****"]);
    assert_eq!(hits("password is Zq7Lm2X*"), vec!["Zq7Lm2X*"]);
    assert_eq!(hits("my password is hunter2}}}"), vec!["hunter2}}}"]);
}

#[test]
fn any_named_key_in_marks_masks_the_value_after_is() {
    // K15 seal r1: underscore marks, camelCase and env-style names.
    for text in [
        "__token__ is Zq7Lm2Xr",
        "_secret_ was Zq7Lm2Xr",
        "__api_key__ is Zq7Lm2Xr",
        "`clientSecret` is Zq7Lm2Xr",
        "\u{201c}accessToken\u{201d} is Zq7Lm2Xr",
        "`authToken` was Zq7Lm2Xr",
        "\u{201c}private_key\u{201d} is Zq7Lm2Xr",
        "`privateKey` is Zq7Lm2Xr",
        "`OPENAI_API_KEY` is Zq7Lm2Xr",
        "the `GITHUB_TOKEN` is Zq7Lm2Xr",
    ] {
        let found = hits(text);
        assert!(
            found.iter().any(|hit| hit.contains("Zq7Lm2Xr")),
            "{text} leaked: {found:?}"
        );
    }
    assert!(hits("the `status` is Zq7Lm2Xr").is_empty());
}

#[test]
fn a_prose_key_followed_by_a_stopword_masks_nothing() {
    assert!(hits("the password manager").is_empty());
    assert!(hits("reset the password for Camille").is_empty());
    assert!(hits("the api key field").is_empty());
    assert!(hits("pwd").is_empty());
    // A dash flag is a secret only in a MySQL or user command.
    assert!(hits("ssh -pTr0ubCliP42 host").is_empty());
}

#[test]
fn a_phrase_scan_reads_each_cue_a_bounded_span() {
    // Cues glued in one long word, and cues one after another, stay linear.
    for text in [
        format!("pin is {}", "a-pin-".repeat(50_000)),
        "pin ".repeat(75_000),
        format!("password for {}", "the ".repeat(75_000)),
        "mot de passe du ".repeat(20_000),
        "mdp est Tr0ub4dor ".repeat(20_000),
        "**password** is Tr0ub4dor ".repeat(20_000),
        "password is set to Tr0ub4dor ".repeat(20_000),
        "-password-".repeat(50_000),
        "__mot-de-passe__ du ".repeat(20_000),
        "`pwd` is the same as ".repeat(20_000),
    ] {
        // The fastest of nine runs, after one warm-up: the bound is on the
        // work, not on the scheduler.
        let elapsed = timing::fastest(|| {
            let _ = hits(&text);
        });
        assert!(elapsed < std::time::Duration::from_secs(5));
    }
}
