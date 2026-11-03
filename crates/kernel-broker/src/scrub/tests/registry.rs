//! Registry lifecycle: eviction order, pins, the cap and hard ceiling, and
//! the home/.env sources a daemon loads its keys from.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_registration_touches_the_eviction_order() {
        // SB6-07: the value that is still being re-resolved must not be the
        // next one evicted; a duplicate registration is a "use" of the key.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        for index in 0..MAX_KNOWN_SECRETS {
            register_known_secret(&format!("CANARY_KS_LRU_{index:04}_7f3a9c2e1b5d"));
        }
        let touched = "CANARY_KS_LRU_0000_7f3a9c2e1b5d";
        assert!(!register_known_secret(touched), "already registered");
        register_known_secret("CANARY_KS_LRU_FRESH_7f3a9c2e1b5d");
        assert!(
            redact_known_secrets(&format!("use {touched} now")).is_some(),
            "the touched key is the one that must survive eviction"
        );
        let next_oldest = "CANARY_KS_LRU_0001_7f3a9c2e1b5d";
        assert!(
            redact_known_secrets(&format!("use {next_oldest} now")).is_none(),
            "the least recently registered key must be evicted"
        );
        clear_known_secrets();
    }

    #[test]
    fn short_values_are_not_registered() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        assert!(!register_known_secret("short12"));
        assert!(!register_known_secret("   "));
        assert!(streaming_hold_bytes() >= MIN_STREAM_WINDOW);
        assert!(redact_known_secrets("short12 stays").is_none());
        clear_known_secrets();
    }

    #[test]
    fn debug_output_never_contains_the_value() {
        let secret = unique("DEBUG");
        let known = KnownSecret::new(&secret, 0);
        let printed = format!("{known:?}");
        assert!(printed.contains("<redacted>"), "{printed}");
        assert!(!printed.contains(&secret), "{printed}");
        let registry = Registry {
            values: vec![KnownSecret::new(&secret, 0)],
            ..Registry::default()
        };
        let printed = format!("{registry:?}");
        assert!(!printed.contains(&secret), "{printed}");
    }

    #[test]
    fn home_registration_reads_dotenv_and_api_token() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let dir = tempfile::tempdir().unwrap();
        let env_secret = unique("ENVFILE");
        let telegram_secret = unique("TELEGRAM");
        let token_secret = unique("APITOKEN");
        std::fs::write(
                dir.path().join(ENV_FILE),
                format!("# comment\nexport AUX_KEY_TESTKEY=\"{env_secret}\"\nAUX_TELEGRAM_BOT_TOKEN=\"{telegram_secret}\"\nOTHER=not-registered\n"),
            )
            .unwrap();
        std::fs::write(dir.path().join(API_TOKEN_FILE), format!("{token_secret}\n")).unwrap();
        let registered = register_known_secrets_from_home(dir.path());
        assert!(registered >= 3, "registered {registered}");
        let raw = format!("{env_secret} and {telegram_secret} and {token_secret}");
        let clean = redact_known_secrets(&raw).expect("both must match");
        assert!(!clean.contains(&env_secret), "{clean}");
        assert!(!clean.contains(&telegram_secret), "{clean}");
        assert!(!clean.contains(&token_secret), "{clean}");
        assert!(redact_known_secrets("not-registered").is_none());
        clear_known_secrets();
    }

    #[test]
    fn home_registration_reads_mail_passwords_and_extension_oauth_tokens() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let dir = tempfile::tempdir().unwrap();
        let mail_password = unique("MAILPASS");
        let access = unique("OAUTHACCESS");
        let refresh = unique("OAUTHREFRESH");
        let bundle = format!(
            r#"{{"access_token":"{access}","refresh_token":"{refresh}","expires_at":4102444800,"scopes":["mail"],"token_type":"Bearer"}}"#
        );
        std::fs::write(
            dir.path().join(ENV_FILE),
            format!(
                "AUX_MAIL_PERSONAL={mail_password}\n\
                     EXT_DEMO__OAUTH_TOKENS={bundle}\n\
                     OTHER=not-registered\n"
            ),
        )
        .unwrap();
        let registered = register_known_secrets_from_home(dir.path());
        assert!(registered >= 4, "registered {registered}");

        // The IMAP repro: a server echoes the mailbox password inside quotes.
        let imap = format!("NO [ALERT] wrong password \"{mail_password}\"");
        let clean = redact_known_secrets(&imap).expect("mail password must be registered");
        assert!(clean.contains(MASK), "{clean}");
        assert!(!clean.contains(&mail_password), "{clean}");
        assert!(
            clean.contains('"'),
            "surrounding text must survive: {clean}"
        );

        // The whole token bundle, and the individual tokens a provider error
        // echoes without the JSON around them, are both secrets.
        let clean = redact_known_secrets(&format!("EXT_DEMO__OAUTH_TOKENS={bundle}"))
            .expect("the token bundle must be registered");
        assert!(!clean.contains(&access), "{clean}");
        assert!(!clean.contains(&refresh), "{clean}");
        for token in [&access, &refresh] {
            let clean = redact_known_secrets(&format!("Authorization: Bearer {token}"))
                .unwrap_or_else(|| panic!("token {token:?} must be registered"));
            assert!(clean.contains(MASK), "{clean}");
            assert!(!clean.contains(token), "{clean}");
        }
        assert!(redact_known_secrets("not-registered").is_none());
        clear_known_secrets();
    }

    #[test]
    fn known_secret_names_cover_mail_and_oauth_only() {
        for name in [
            "AUX_KEY_DEEPSEEK",
            "AUX_TELEGRAM_BOT_TOKEN",
            "AUX_MAIL_PERSONAL",
            "AUX_MAIL_WORK_MAIL",
            "EXT_DEMO__OAUTH_TOKENS",
        ] {
            assert!(is_known_secret_name(name), "{name}");
        }
        for name in [
            "AUX_MAILBOX_HOST",
            "AUX_MAIL",
            "EXT_DEMO__CLIENT_SECRET",
            "OAUTH_TOKENS",
            "OTHER",
        ] {
            assert!(!is_known_secret_name(name), "{name}");
        }
    }

    #[test]
    fn pinned_secrets_survive_eviction_and_unpin_trims() {
        // R7-1: a value a live stream relies on must not be evicted by the
        // LRU cap; releasing the pin trims the registry back to the cap.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let live = unique("PINNED");
        assert!(register_known_secret(&live));
        let epoch = pin_known_secrets();
        for index in 0..MAX_KNOWN_SECRETS + 8 {
            register_known_secret(&format!("CANARY_KS_PIN_{index:04}_7f3a9c2e1b5d"));
        }
        assert!(
            redact_known_secrets(&format!("use {live} now")).is_some(),
            "a pinned value must survive cap pressure"
        );
        assert!(
            read_registry().values.len() <= MAX_KNOWN_SECRETS,
            "unpinned values must still be evicted at the cap"
        );
        // Pin everything, then the registry may exceed the cap temporarily.
        let second = pin_known_secrets();
        for index in 0..8 {
            register_known_secret(&format!("CANARY_KS_PINB_{index:04}_7f3a9c2e1b5d"));
        }
        assert!(
            read_registry().values.len() > MAX_KNOWN_SECRETS,
            "an all-pinned registry may exceed the cap until the streams end"
        );
        unpin_known_secrets(second);
        assert_eq!(
            read_registry().values.len(),
            MAX_KNOWN_SECRETS,
            "releasing a pin trims the registry back to the cap"
        );
        assert!(
            redact_known_secrets(&format!("use {live} now")).is_some(),
            "the first pin still protects its value"
        );
        unpin_known_secrets(epoch);
        clear_known_secrets();
    }

    /// R8 (3): with every value pinned, the registry grows to the hard
    /// ceiling and then refuses new values (streams fail closed) instead of
    /// evicting a pinned value. The pinned target survives.
    #[test]
    fn all_pinned_registry_refuses_new_values_at_the_hard_ceiling() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let target = unique("PINHARD");
        assert!(register_known_secret(&target));
        for index in 0..MAX_KNOWN_SECRETS - 1 {
            register_known_secret(&format!("CANARY_KS_HARDFILL_{index:04}_7f3a9c2e1b5d"));
        }
        assert_eq!(read_registry().values.len(), MAX_KNOWN_SECRETS);
        let mut epochs = vec![pin_known_secrets()];
        // Grow to the hard ceiling with every value pinned.
        for index in 0..MAX_KNOWN_SECRETS_HARD {
            if registry_saturated() {
                break;
            }
            register_known_secret(&format!("CANARY_KS_HARDGROW_{index:04}_7f3a9c2e1b5d"));
            epochs.push(pin_known_secrets());
        }
        assert!(
            registry_saturated(),
            "the registry must report saturation at the hard ceiling"
        );
        assert_eq!(read_registry().values.len(), MAX_KNOWN_SECRETS_HARD);
        // A new value is refused rather than evicting a pinned one.
        assert!(
            !register_known_secret("CANARY_KS_HARDOVER_7f3a9c2e1b5d"),
            "a new value must be refused at the hard ceiling"
        );
        assert!(
            redact_known_secrets(&format!("use {target} now")).is_some(),
            "the pinned target must never be evicted"
        );
        assert_eq!(
            read_registry().values.len(),
            MAX_KNOWN_SECRETS_HARD,
            "a refusal must not grow the registry further"
        );
        for epoch in epochs {
            unpin_known_secrets(epoch);
        }
        assert!(
            read_registry().values.len() <= MAX_KNOWN_SECRETS,
            "unpinning must trim back to the cap"
        );
        assert!(!registry_saturated());
        clear_known_secrets();
    }

    #[test]
    fn registration_never_grows_past_the_cap() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        for index in 0..MAX_KNOWN_SECRETS + 8 {
            let value = format!("CANARY_KS_CAP_{index:04}_7f3a9c2e1b5d");
            register_known_secret(&value);
        }
        let registry = read_registry();
        assert_eq!(registry.values.len(), MAX_KNOWN_SECRETS);
        drop(registry);
        // The newest registration survived the eviction of the oldest.
        let newest = format!("CANARY_KS_CAP_{:04}_7f3a9c2e1b5d", MAX_KNOWN_SECRETS + 7);
        assert!(
            redact_known_secrets(&format!("use {newest} now")).is_some(),
            "the newest key must still register at the cap"
        );
        let oldest = "CANARY_KS_CAP_0000_7f3a9c2e1b5d";
        assert!(
            redact_known_secrets(&format!("use {oldest} now")).is_none(),
            "the evicted oldest key must not match"
        );
        clear_known_secrets();
    }
}
