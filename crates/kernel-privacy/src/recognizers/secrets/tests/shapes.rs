//! Key shapes, glued keys and wrapped continuations.

use super::super::glued::plainly_words;
use super::*;

#[test]
fn a_key_is_one_span_with_its_prefix() {
    let key = concat!("sk-proj-", "FAKEKEY0123456789abcdefGHIJKL");
    assert_eq!(hits(&format!("key {key} end")), vec![key]);
}

#[test]
fn a_lower_case_aws_key_is_masked_and_akia_words_are_not() {
    let key = concat!("akia", "iosfodnn7example");
    assert_eq!(hits(&format!("key {key}.")), vec![key]);
    // SECRET-1: a word glued after the key no longer hides it; SECRET-2:
    // the glued suffix goes with it.
    assert_eq!(hits(&format!("{key}s")), vec![format!("{key}s")]);
    for text in [format!("x{key}"), key[..19].to_string()] {
        assert!(hits(&text).is_empty(), "{text} is masked");
    }
}

#[test]
fn a_short_sk_word_is_not_a_key() {
    assert!(hits("the sk-learn package").is_empty());
}

#[test]
fn a_key_glued_to_a_word_is_still_a_key() {
    let key = concat!("sk-", "aB3dE6gH9jK2mN5pQ8sT1vW4xY7zA0cD3fG6hJ9kL2mN5pQ8");
    assert_eq!(hits(&format!("task-{key}")), vec![key]);
    assert_eq!(hits(&format!("我的{key}")), vec![key]);
}

#[test]
fn glued_key_masks_only_key_and_leaves_identifier_suffix_clear() {
    let key = concat!("sk-", "aB3dE6gH9jK2mN5pQ8sT1vW4xY7zA0cD3fG6hJ9kL2mN5pQ8");
    for suffix in [" next", "_build_id", "-release_notes", ".env"] {
        let text = format!("task-{key}{suffix}");
        assert_eq!(hits(&text), vec![key], "{suffix}");
    }
}

#[test]
fn long_camel_and_kebab_identifiers_are_not_glued_keys() {
    let long = "calculateTotalAmountForUserAccountBalanceInEuros2024";
    assert!(plainly_words(&format!("sk-{long}")));
    for prefix in ["desk-", "mask-", "whisk-", "ask-"] {
        let text = format!("{prefix}{long}");
        assert!(hits(&text).is_empty(), "{text}");
    }
    for text in [
        concat!(
            "ta",
            "sk-",
            "calculateTotalAmountForUserAccountBalanceInEuros2024"
        ),
        concat!(
            "ri",
            "sk-",
            "assessmentForQuarterlyReportGenerationAndReview2025"
        ),
        concat!(
            "ri",
            "sk-",
            "assessment-for-quarterly-report-generation-and-review-2025"
        ),
        "desk-",
        "mask-",
        "whisk-",
        "ask-",
        "task-calculate_total_amount_for_user_account_balance_in_euros_2024",
        "lib/kernel_privacy/src/recognizers/secrets.rs",
    ] {
        assert_eq!(hits(text), Vec::<&str>::new(), "{text}");
    }
}

#[test]
fn a_project_key_with_suffix_stops_at_the_64_byte_body() {
    let key = format!("sk-proj-{}a", "aB3".repeat(21));
    assert_eq!(key.len(), 72);
    for suffix in ["", ".", "x", "7", "_", "-"] {
        assert_eq!(
            hits(&format!("n{key}{suffix}")),
            vec![key.as_str()],
            "{suffix}"
        );
    }
}

#[test]
fn a_wrapped_key_joins_its_continuation_run() {
    assert_eq!(
        hits("sk-proj-FAKEKEY0123\nFAKEKEY456 end"),
        vec!["sk-proj-FAKEKEY0123\nFAKEKEY456"]
    );
}

#[test]
fn a_line_that_does_not_open_with_key_alphabet_ends_the_key() {
    assert_eq!(
        hits("sk-proj-FAKEKEY0123456789\n: the rest"),
        vec!["sk-proj-FAKEKEY0123456789"]
    );
}

#[test]
fn the_join_stops_after_the_line_cap() {
    let text = "sk-a\n".repeat(10_000);
    let spans = SecretRecognizer::new().analyze(&text);
    assert!(spans
        .iter()
        .all(|span| span.end - span.start <= MAX_WRAP_BYTES + 5));
}

#[test]
fn a_key_at_a_line_end_does_not_join_the_next_key() {
    // A config file has one key per line: the next line's `NAME=` or `NAME:`
    // is a key, not a wrapped continuation of the token above it.
    assert_eq!(
        hits("sntrys_FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz\nLOG_LEVEL=info"),
        vec!["sntrys_FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz"]
    );
    assert_eq!(
        hits("sk-proj-FAKEKEY0123456789\nendpoint: x"),
        vec!["sk-proj-FAKEKEY0123456789"]
    );
    // Base64 padding is not a separator: a wrapped `AB==` still joins.
    assert_eq!(
        hits("sk-proj-FAKEKEY0123456789\nAB=="),
        vec!["sk-proj-FAKEKEY0123456789\nAB"]
    );
}

#[test]
fn htpasswd_with_i_reads_stdin_so_the_word_after_the_user_stays_clear() {
    // The same lines without `-i` mask `reads`: only the `-i` skip keeps it clear.
    let lines = [
        ("-B", " users.db", &["-i -B", "-iB"]),
        (
            "-B -r 1000000",
            " users.db",
            &["-i -B -r 1000000", "-iB -r 1000000"],
        ),
    ];
    for (flags, file, skips) in lines {
        let line = format!("htpasswd {flags}{file} kim reads stdin");
        assert!(hits(&line).contains(&"reads"), "{line}: {:?}", hits(&line));
        for skip in skips {
            let line = format!("htpasswd {skip}{file} kim reads stdin");
            assert!(!hits(&line).contains(&"reads"), "{line}: {:?}", hits(&line));
        }
    }
}

#[test]
fn htpasswd_n_with_i_still_masks_what_main_masks() {
    // Strict superset: main's `-n` rule ignores `-i`, so these words stay masked.
    for flags in ["-nb -i", "-nbi", "-nB -i", "-i -nB", "-ni -b"] {
        let line = format!("htpasswd {flags} kim reads stdin");
        assert!(hits(&line).contains(&"reads"), "{line}: {:?}", hits(&line));
    }
}

#[test]
fn a_quoted_htpasswd_user_takes_only_a_quoted_or_secret_shaped_password() {
    // Main masks `smith"` here; the word after the quoted user stays clear.
    let line = "htpasswd -b site.db \"alice smith\" then restart";
    assert!(
        clear_of(line).ends_with(" then restart"),
        "{:?}",
        hits(line)
    );
    assert!(hits(line).contains(&"smith\""), "{:?}", hits(line));
    for password in ["\"my pass word\"", "S3cretPass"] {
        let line = format!("htpasswd -b site.db \"alice smith\" {password} now");
        assert!(hits(&line).contains(&password), "{line}: {:?}", hits(&line));
    }
}

#[test]
fn a_quoted_htpasswd_user_takes_a_plain_password_that_ends_the_command() {
    for line in [
        "htpasswd -b site.db \"alice smith\" correcthorse",
        "htpasswd -b site.db \"alice smith\" correcthorse\r\nnext",
        "htpasswd -bB site.db 'alice smith' correcthorse && nginx -s reload",
        "htpasswd -b site.db \"alice smith\" correcthorse > /dev/null",
        "htpasswd -b site.db \"alice smith\" correcthorse 2>/dev/null",
        "htpasswd -b site.db \"alice smith\" correcthorse 2>&1",
        "htpasswd -b site.db \"alice smith\" correcthorse # rotate",
        "htpasswd -b site.db \"alice smith\" correcthorse \\\n  && reload",
    ] {
        assert!(
            hits(line).contains(&"correcthorse"),
            "{line:?}: {:?}",
            hits(line)
        );
    }
    // A word with more prose after it stays clear, as on main.
    let line = "htpasswd -b site.db \"alice smith\" then restart";
    assert!(
        clear_of(line).ends_with(" then restart"),
        "{:?}",
        hits(line)
    );
}

#[test]
fn the_three_ssws_paths_agree_on_a_token() {
    let letters = "FakeOktaTokenLettersOnlyNoDigitsAbcdEfGhIj";
    assert_eq!(letters.len(), 42);
    for frame in [
        "SSWS: {}",
        "ssws: {}",
        "SSWS token\n\n{}",
        "ssws header:\n\n\n\n{}",
        "ssws {}",
    ] {
        let line = frame.replace("{}", &letters.to_ascii_lowercase());
        assert!(
            hits(&line).contains(&letters.to_ascii_lowercase().as_str()),
            "{line:?}"
        );
    }
    // An 8–19-character token with no digit after `SSWS:`, in any case.
    for line in ["SSWS: abcdefgh", "ssws: abcdefgh", "Ssws: 'fakeoktavalue'"] {
        let value = line
            .rsplit(' ')
            .next()
            .unwrap_or_default()
            .trim_matches('\'');
        assert!(hits(line).contains(&value), "{line:?}: {:?}", hits(line));
    }
    for line in [
        "SSWS: required",
        "SSWS: credentials",
        "SSWS: login.example.com",
        "SSWS token\n\n\n\n\nThisIsALongIdentifierName",
    ] {
        assert!(hits(line).is_empty(), "{line:?}: {:?}", hits(line));
    }
}
