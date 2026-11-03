//! Tests for the redaction corpus: canaries, false positives and the
//! documented secret shapes.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    mod redaction_canaries {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/redaction_canaries.rs"
        ));
    }

    /// The full round-2 canary corpus, assembled at runtime so no
    /// vendor-shaped literal is committed (the repo secret scanner must not
    /// find fixtures; values are synthetic either way).
    fn canaries() -> Vec<(String, String)> {
        let mut cases: Vec<(String, String)> = Vec::new();
        let mut add = |raw: String, secret: &str| cases.push((raw, secret.to_string()));

        // --- round 1: assignments, prefixes, PEM, JWT, env ---
        add("DB_PASSWORD=CANARYSECRET123".into(), "CANARYSECRET123");
        add(
            "MY_SERVICE_PASSWORD=CANARYSECRET123".into(),
            "CANARYSECRET123",
        );
        add(
            "GITHUB_CANCELLATION_TOKEN=x\ntoken=CANARYSECRET123".into(),
            "CANARYSECRET123",
        );
        add(
            "notatoken=1 then token=CANARYSECRET123".into(),
            "CANARYSECRET123",
        );
        add(
            "x-token=old and token=CANARYSECRET123".into(),
            "CANARYSECRET123",
        );
        add(
            "api_key=<redacted> markerapi_key allowed — api_key=CANARYSHOP8 markerapi_key".into(),
            "CANARYSHOP8",
        );
        add(
            format!("AKIA{}", "CANARYSHOP4AAA111BBB"),
            "CANARYSHOP4AAA111BBB",
        );
        add(
            format!("ghp_{}", "CANARYSHOP3aaa111bbb"),
            "CANARYSHOP3aaa111bbb",
        );
        add(format!("sk-{}", "canary-SHOP1aaa111"), "canary-SHOP1aaa111");
        add(format!("xoxb-1111-2222-{}", "CANARYSHOP5"), "CANARYSHOP5");
        add("api_key=CANARYSHOP8".into(), "CANARYSHOP8");
        add("password=CANARYSHOP9".into(), "CANARYSHOP9");
        add(
            format!(
                "eyJhbGciOiJIUzI1NiJ9.{}.sig{}",
                "eyJzdWIiOiJDQU5BUlkifQ", "CANARYSHOP6"
            ),
            "CANARYSHOP6",
        );
        add(
            "export AUX_KEY_DEEPSEEK = AUXCANARYSPACED42".into(),
            "AUXCANARYSPACED42",
        );
        add(
            "export AUX_KEY_DEEPSEEK\t=\tAUXCANARYTABBED43".into(),
            "AUXCANARYTABBED43",
        );
        add("ANTHROPIC_API_KEY=CANARYSHOP11".into(), "CANARYSHOP11");
        add(
            "AWS_SECRET_ACCESS_KEY=CANARYawssecret51".into(),
            "CANARYawssecret51",
        );
        add("GITHUB_TOKEN=CANARYghenv54".into(), "CANARYghenv54");
        add("accessToken=CANARYE2ECAMEL18".into(), "CANARYE2ECAMEL18");
        add("dbPassword=CANARYE2ECAMEL19".into(), "CANARYE2ECAMEL19");
        add(
            "secretAccessKey=CANARYE2ECAMEL20".into(),
            "CANARYE2ECAMEL20",
        );
        add(
            "client_secret=CANARYclientsecret50".into(),
            "CANARYclientsecret50",
        );
        add("secret=CANARYsecretword52".into(), "CANARYsecretword52");
        add("api_key=abcdef123456ghi".into(), "abcdef123456ghi");
        add("apikey=abcdef123456ghi".into(), "abcdef123456ghi");
        add("api-key=abcdef123456ghi".into(), "abcdef123456ghi");
        add("token=abcdef123456ghi".into(), "abcdef123456ghi");
        add("password=hunter2swordfish".into(), "hunter2swordfish");
        add("PASSWORD = \"two words secret\"".into(), "two words secret");
        add("Token=0123456789abcdef".into(), "0123456789abcdef");
        add(
            format!("github_pat_{}", "11ABCDEFG0CANARYSHOP2abcdefghij"),
            "11ABCDEFG0CANARYSHOP2abcdefghij",
        );

        // --- B2-01: colon/`:=`/JSON/YAML/ini spellings ---
        add(
            "{\"api_key\":\"CANARYJSONKEY0001\"}".into(),
            "CANARYJSONKEY0001",
        );
        add(
            "{\"password\":\"CANARYE2EJSON02\"}".into(),
            "CANARYE2EJSON02",
        );
        add("{\"token\":\"CANARYE2EJSON03\"}".into(), "CANARYE2EJSON03");
        add(
            "{\"client_secret\":\"CANARYE2EJSON04\"}".into(),
            "CANARYE2EJSON04",
        );
        add(
            "{\"AUX_KEY_DEEPSEEK\":\"CANARYE2EENV10\"}".into(),
            "CANARYE2EENV10",
        );
        add("api_key: CANARYE2EYAML02".into(), "CANARYE2EYAML02");
        add("  password: CANARYE2EYAML05".into(), "CANARYE2EYAML05");
        add("password:CANARYE2ECOLON03".into(), "CANARYE2ECOLON03");
        add("[creds]\napi_key: CANARYE2EINI04".into(), "CANARYE2EINI04");
        add("TOKEN: CANARYE2EUPPER05".into(), "CANARYE2EUPPER05");
        add("token := CANARYE2EWALRUS06".into(), "CANARYE2EWALRUS06");
        add(format!("api_key%3D{}", "CANARYE2EPCT12"), "CANARYE2EPCT12");
        add(
            format!(
                "{{\"api_key\":\"{}\"}} unknown tool.decision",
                "CANARYE2EJSON01"
            ),
            "CANARYE2EJSON01",
        );

        // --- B2-02: URL/URI userinfo + url/uri/webhook names ---
        add(
            "postgres://app:CANARYE2EURL04@db.internal:5432/prod".into(),
            "CANARYE2EURL04",
        );
        add(
            "mongodb+srv://u:CANARYE2EURL05@cluster0/db".into(),
            "CANARYE2EURL05",
        );
        add(
            "redis://:CANARYE2EURL06@cache:6379/0".into(),
            "CANARYE2EURL06",
        );
        add(
            "amqp://guest:CANARYE2EURL07@mq:5672/%2f".into(),
            "CANARYE2EURL07",
        );
        add(
            "https://svc:CANARYE2EURL08@internal.example/db".into(),
            "CANARYE2EURL08",
        );
        add(
            "proxy=https://user:CANARYE2EURL09@proxy:3128".into(),
            "CANARYE2EURL09",
        );
        add(
            "DATABASE_URL=postgres://u:CANARYE2EURL10@h/d".into(),
            "CANARYE2EURL10",
        );
        add(
            format!(
                "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/{}/B00/xx",
                "CANARYHOOK0004"
            ),
            "CANARYHOOK0004",
        );

        // --- B2-03: credential headers ---
        add(
            "X-Api-Key: CANARYE2EHDR06ABCDEFGHIJ".into(),
            "CANARYE2EHDR06ABCDEFGHIJ",
        );
        add(
            "X-Auth-Token: CANARYE2EHDR07ABCDEFGHIJ".into(),
            "CANARYE2EHDR07ABCDEFGHIJ",
        );
        add(
            "Proxy-Authorization: Basic Q0FOQVNZVlJFTEIzNDU2Nzg5".into(),
            "Q0FOQVNZVlJFTEIzNDU2Nzg5",
        );
        add(
            "Cookie: session=CANARYE2ECOOKIE07abcdefghij".into(),
            "CANARYE2ECOOKIE07abcdefghij",
        );
        add(
            "X-Hub-Signature-256: sha256=CANARYE2EHDR08abcdef".into(),
            "CANARYE2EHDR08abcdef",
        );

        // --- B2-05: passphrase / credential(s) ---
        add("GPG_PASSPHRASE=CANARYE2EPASS08".into(), "CANARYE2EPASS08");
        add("SSH_PASSPHRASE=CANARYE2EPASS09".into(), "CANARYE2EPASS09");
        add("AWS_CREDENTIALS=CANARYE2ECRED10".into(), "CANARYE2ECRED10");
        add("DB_CREDENTIAL=CANARYE2ECRED11".into(), "CANARYE2ECRED11");

        // --- B2-06: PEM labels + PuTTY ---
        add(
            format!(
                "-----BEGIN private key-----\n{}\n-----END private key-----",
                "CANARYPEM0005abcdefgh"
            ),
            "CANARYPEM0005abcdefgh",
        );
        add(
            format!(
                "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: test\n\
                 Public-Lines: 6\nAAAAB3NzaC1yc2E\nPrivate-Lines: 2\n{}\nPrivate-MAC: deadbeef",
                "CANARYPUTTY0004abcdefgh"
            ),
            "CANARYPUTTY0004abcdefgh",
        );

        // --- B2-09/B2-11: shape bands and error-body URL credentials ---
        add("Bearer abcdefghijklmnopqrst".into(), "abcdefghijklmnopqrst");
        add(
            "Authorization: 0123456789abcdef0123456789abcdef".into(),
            "0123456789abcdef0123456789abcdef",
        );
        add("http://CANARYE2EERR13@[".into(), "CANARYE2EERR13");
        add(
            format!("curl -u user:{} https://example.com", "CANARYE2ECURL16"),
            "CANARYE2ECURL16",
        );

        // --- round 5: brackets, padded keys, folded schemes, sibling pairs ---
        add(
            format!("api_key=({})", "CANARY_B5_01_PAREN01"),
            "CANARY_B5_01_PAREN01",
        );
        add(
            format!("password=({})", "CANARY_B5_01_PASSW02"),
            "CANARY_B5_01_PASSW02",
        );
        add(
            format!("api_key=<{}>", "CANARY_B5_01_ANGLE3"),
            "CANARY_B5_01_ANGLE3",
        );
        add(
            format!("{{ \" api_key \" : \"{}\" }}", "CANARY_B5_02_PADDED4"),
            "CANARY_B5_02_PADDED4",
        );
        add(
            format!("{{ \"api_key \" : \"{}\"}}", "CANARY_B5_02_PADDED5"),
            "CANARY_B5_02_PADDED5",
        );
        add(
            format!("Bearer\n {}", "CANARY_B5_04_FOLDED06"),
            "CANARY_B5_04_FOLDED06",
        );
        add(
            format!("Basic\n {}", "YWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
            "YWxhZGRpbjpvcGVuIHNlc2FtZQ",
        );
        add(
            format!(
                "{{\"name\":\"api_key\",\"value\":\"{}\"}}",
                "CANARY_E5_01_NAME07"
            ),
            "CANARY_E5_01_NAME07",
        );
        add(
            format!(
                "{{\"key\":\"api_key\",\"value\":\"{}\"}}",
                "CANARY_E5_01_KEY08"
            ),
            "CANARY_E5_01_KEY08",
        );
        add(
            format!(
                "{{\"field\":\"password\",\"content\":\"{}\"}}",
                "CANARY_E5_01_FIELD9"
            ),
            "CANARY_E5_01_FIELD9",
        );
        add(
            format!(
                "{{\"arguments\":{{\"name\":\"api_key\",\"value\":\"{}\"}}}}",
                "CANARY_E5_01_ARG10"
            ),
            "CANARY_E5_01_ARG10",
        );
        add(
            format!("[\"api_key\",\"{}\"]", "CANARY_E5_01_ARRAY1"),
            "CANARY_E5_01_ARRAY1",
        );
        add(
            format!(
                "{{\"variable\":\"DB_PASSWORD\",\"val\":\"{}\"}}",
                "CANARY_E5_01_VAR12"
            ),
            "CANARY_E5_01_VAR12",
        );
        add(
            format!("[\"Authorization\",\"Bearer {}\"]", "CANARY_E5_01_AUTH13"),
            "CANARY_E5_01_AUTH13",
        );

        cases
    }

    /// False-positive corpus: text that must survive `redact_secrets` byte for
    /// byte, paired with the substring that proves it.
    fn false_positives() -> Vec<(String, String)> {
        let mut cases: Vec<(String, String)> = Vec::new();
        let mut add = |raw: &str, keep: &str| cases.push((raw.to_string(), keep.to_string()));

        add("disk-usage is high", "disk-usage");
        add("The Bearer bonds are up", "Bearer bonds");
        add("Tokenization of the input", "Tokenization");
        add("AKIA is just a prefix", "AKIA is just a prefix");
        add(
            "-----BEGIN CERTIFICATE-----\nMIICcanaryCERT\n-----END CERTIFICATE-----",
            "MIICcanaryCERT",
        );
        add("check_id=1234 and password=short", "password=short");
        add("api_key= query parameter", "api_key= query parameter");
        add("token = ", "token =");
        add("eyJhbGciOiJIUzI1NiJ9", "eyJhbGciOiJIUzI1NiJ9");
        add(
            "authorization is required for this route",
            "authorization is required",
        );
        add("I withdrew 100 USD from the bank", "I withdrew 100 USD");
        add("task-sk-1234", "task-sk-1234");
        add("disk-sk-usage", "disk-sk-usage");
        add("risk-sk-1", "risk-sk-1");
        add("public_key_sha256 = 9f2a1b3c", "9f2a1b3c");
        add("let token = parse(input);", "parse(input)");
        add("key = \"abcdefghijkl\"", "abcdefghijkl");
        add(
            "commit 9f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90",
            "9f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90",
        );
        add(
            "sha256=3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3",
            "3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3",
        );
        add(
            "https://example.com/docs?page=2",
            "https://example.com/docs?page=2",
        );
        add("homepage_url=https://example.com", "https://example.com");
        add(
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
            "iVBORw0KGgo",
        );
        add("{\"token\":\"abc\"}", "{\"token\":\"abc\"}");
        add("version: 1.2.3", "version: 1.2.3");
        add("at 12:30:45 the job ran", "12:30:45");
        add(
            "Please rotate the API key in the console",
            "API key in the console",
        );
        add("your password policy", "your password policy");
        add("token bucket rate limiting", "token bucket rate limiting");
        add(
            "The credentials should never be committed",
            "credentials should never",
        );
        add(
            "fn check_key(token: &str) -> bool { token.len() > 0 }",
            "fn check_key(token: &str)",
        );
        add("password: required", "password: required");
        add("token: None", "token: None");
        add("assignment: 1234", "assignment: 1234");
        add("mailto:user@example.com", "mailto:user@example.com");
        add("https://example.com/a@b", "https://example.com/a@b");
        add(
            "Content-Security-Policy: default-src 'self'",
            "Content-Security-Policy",
        );
        add("Secret Santa gift exchange", "Secret Santa");
        add(
            "base_url = \"https://api.example.com/v1\"",
            "https://api.example.com/v1",
        );

        cases
    }

    #[test]
    fn redaction_covers_the_documented_secret_shapes() {
        // (raw text, secret that must not survive)
        let cases: &[(&str, &str)] = &[
            ("token sk-canary-abcdef123456 end", "sk-canary-abcdef123456"),
            (
                "env AUX_KEY_DEEPSEEK=sk-live-abcdef12345 done",
                "sk-live-abcdef12345",
            ),
            (
                "pushed ghp_0123456789abcdefghijklmnopqrstuvwx to the remote",
                "ghp_0123456789abcdefghijklmnopqrstuvwx",
            ),
            (
                "PAT github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz0123456789",
                "github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz0123456789",
            ),
            ("key id AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"),
            (
                "slack xoxb-123456789012-abcdefghijklmnopqrstuvwx",
                "xoxb-123456789012-abcdefghijklmnopqrstuvwx",
            ),
            (
                "slack xoxp-123456789012-abcdefghijklmnopqrstuvwx",
                "xoxp-123456789012-abcdefghijklmnopqrstuvwx",
            ),
            (
                "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
                "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            ),
            (
                "auth Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            ),
            (
                "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAcanary\n-----END RSA PRIVATE KEY-----",
                "MIIEowIBAAKCAQEAcanary",
            ),
            ("api_key=abcdef123456ghi", "abcdef123456ghi"),
            ("apikey=abcdef123456ghi", "abcdef123456ghi"),
            ("api-key=abcdef123456ghi", "abcdef123456ghi"),
            ("token=abcdef123456ghi", "abcdef123456ghi"),
            ("password=hunter2swordfish", "hunter2swordfish"),
            ("PASSWORD = \"two words secret\"", "two words secret"),
            ("Token=0123456789abcdef", "0123456789abcdef"),
        ];
        for (raw, secret) in cases {
            let clean = redact_secrets(raw);
            assert!(!clean.contains(secret), "leaked {secret:?} in {clean:?}");
            assert!(clean.contains("<redacted>"), "no marker in {clean:?}");
        }
    }

    #[test]
    fn every_canary_in_the_corpus_is_redacted() {
        for (raw, secret) in canaries() {
            let clean = redact_secrets(&raw);
            assert!(!clean.contains(&secret), "leaked {secret:?} in {clean:?}");
            assert!(
                clean.contains("<redacted>"),
                "no marker for {secret:?} in {clean:?}"
            );
        }
    }

    #[test]
    fn shared_secret_redaction_canaries_are_redacted() {
        redaction_canaries::assert_no_canaries(redact_secrets);
    }

    #[test]
    fn canaries_are_redacted_through_every_shared_entry_point() {
        // The API surfaces (activity, WS frames, messages, instructions),
        // notifications and error bodies all funnel into these three
        // functions; none may bypass the shared scrubber.
        let home = Path::new("/Users/secret/.auxesis");
        for (raw, secret) in canaries() {
            let preview = scrub_external_preview(home, &raw, 64 * 1024);
            assert!(
                !preview.contains(&secret),
                "preview leaked {secret:?}: {preview:?}"
            );
            let detail = sanitize_error_detail(home, &raw, 2048);
            assert!(
                !detail.contains(&secret),
                "detail leaked {secret:?}: {detail:?}"
            );
        }
    }

    #[test]
    fn false_positives_survive_every_shared_entry_point() {
        let home = Path::new("/Users/secret/.auxesis");
        for (raw, keep) in false_positives() {
            let clean = redact_secrets(&raw);
            assert!(clean.contains(&keep), "mangled {keep:?} into {clean:?}");
            let preview = scrub_external_preview(home, &raw, 64 * 1024);
            assert!(
                preview.contains(&keep),
                "preview mangled {keep:?} into {preview:?}"
            );
            let detail = sanitize_error_detail(home, &raw, 2048);
            assert!(
                detail.contains(&keep),
                "detail mangled {keep:?} into {detail:?}"
            );
        }
    }

    #[test]
    fn redaction_keeps_ordinary_text_untouched() {
        let cases: &[&str] = &[
            "disk-usage is high",
            "The Bearer bonds are up",
            "Tokenization of the input",
            "AKIA is just a prefix",
            "-----BEGIN CERTIFICATE-----\nMIICcanary\n-----END CERTIFICATE-----",
            "check_id=1234 and password=short",
            "api_key= query parameter",
            "token = ",
            "eyJhbGciOiJIUzI1NiJ9",
            "authorization is required for this route",
            "I withdrew 100 USD from the bank",
        ];
        for raw in cases {
            assert_eq!(redact_secrets(raw), *raw, "ordinary text was rewritten");
        }
    }

    #[test]
    fn vendor_prefixed_names_and_spaced_dotenv_assignments_are_redacted() {
        // P2-4: everything an operator puts in an env file; P2-3: the
        // dotenv-legal `NAME = value` form `parse_dotenv` actually loads.
        let cases: &[(&str, &str)] = &[
            ("ANTHROPIC_API_KEY=CANARYSHOP11", "CANARYSHOP11"),
            (
                "AWS_SECRET_ACCESS_KEY=CANARYawssecret51",
                "CANARYawssecret51",
            ),
            ("OPENAI_API_KEY=CANARYSHOP12", "CANARYSHOP12"),
            ("GITHUB_TOKEN=CANARYghenv54", "CANARYghenv54"),
            ("client_secret=CANARYclientsecret50", "CANARYclientsecret50"),
            ("secret=CANARYsecretword52", "CANARYsecretword52"),
            (
                "export AUX_KEY_DEEPSEEK = AUXCANARYSPACED42",
                "AUXCANARYSPACED42",
            ),
            (
                "export AUX_KEY_DEEPSEEK\t=\tAUXCANARYTABBED43",
                "AUXCANARYTABBED43",
            ),
        ];
        for (raw, secret) in cases {
            let clean = redact_secrets(raw);
            assert!(!clean.contains(secret), "leaked {secret:?} in {clean:?}");
            assert!(clean.contains("<redacted>"), "no marker in {clean:?}");
        }
    }

    #[test]
    fn redaction_preserves_the_spelling_it_matched() {
        // P3-10: the redactor used to re-emit its constant name and swallow
        // the whitespace around `=`, mangling the env-dump text it protects.
        assert_eq!(
            redact_secrets("PASSWORD=CANARYSECRET123"),
            "PASSWORD=<redacted>"
        );
        assert_eq!(redact_secrets("Api_Key=abcdef123456"), "Api_Key=<redacted>");
        assert_eq!(redact_secrets("API-KEY=abcdef123456"), "API-KEY=<redacted>");
        assert_eq!(
            redact_secrets("PASSWORD = \"two words secret\""),
            "PASSWORD = \"<redacted>\""
        );
        // B2-08: `token` here is a code identifier, not an assignment value.
        assert_eq!(
            redact_secrets("let token = parse(input);"),
            "let token = parse(input);"
        );
        // A bare `Authorization: none` is not a secret and must survive.
        assert_eq!(redact_secrets("AUTHORIZATION: none"), "AUTHORIZATION: none");
        assert_eq!(
            redact_secrets("Authorization: off\n"),
            "Authorization: off\n"
        );
        // Idempotent: the mask itself is not re-redacted.
        assert_eq!(redact_secrets("api_key=<redacted>"), "api_key=<redacted>");
        assert_eq!(
            redact_secrets("AUX_KEY_X=<redacted>"),
            "AUX_KEY_X=<redacted>"
        );
    }

    #[test]
    fn a_zero_width_separator_is_stripped_before_redaction() {
        // B2-10: `token\u{200b}=…` is saved by `sanitize_text` on the shipped
        // path, even though the bare pattern redactor cannot see through the
        // invisible byte.
        let home = Path::new("/nonexistent-home");
        let raw = "token\u{200b}=CANARYE2EZWSP17";
        let clean = scrub_external_preview(home, raw, 4096);
        assert!(!clean.contains("CANARYE2EZWSP17"), "{clean}");
        let detail = sanitize_error_detail(home, raw, 512);
        assert!(!detail.contains("CANARYE2EZWSP17"), "{detail}");
    }

    /// dh-1 fidelity note: secret-free text keeps the four bidi isolate
    /// controls byte-for-byte — in prose and inside JSON — while an isolate
    /// that hides a secret is still consumed by the redaction.
    #[test]
    fn secret_free_text_keeps_bidi_isolates_but_they_cannot_hide_a_secret() {
        let home = Path::new("/definitely-not-the-home");
        let prose = "he said \u{2066}hello\u{2067}يا\u{2068}there\u{2069} ok";
        assert_eq!(redact_secrets(prose), prose, "prose was rewritten");
        assert_eq!(
            scrub_external_preview(home, prose, 1 << 20),
            prose,
            "preview was rewritten"
        );
        let json = "{\"msg\":\"mixed \u{2066}rtl\u{2069} text\",\"n\":1}";
        assert_eq!(redact_secrets(json), json, "json was rewritten");
        assert_eq!(
            scrub_external_preview(home, json, 1 << 20),
            json,
            "json preview was rewritten"
        );
        // A lone isolate is content too, but the other controls still go.
        assert_eq!(redact_secrets("\u{2067}"), "\u{2067}");
        assert_eq!(redact_secrets("\u{202e}"), "");

        // An isolate that breaks a heuristic pair (`access_token=…`) must
        // not shield the value from the redactor.
        let pair = "access_token\u{2067}=CANARYISOLATEHEUR1";
        let clean = scrub_external_preview(home, pair, 4096);
        assert!(!clean.contains("CANARYISOLATEHEUR1"), "{clean}");
    }

    #[test]
    fn typography_cjk_and_fullwidth_text_survive_byte_for_byte() {
        // B5-07/H-05: the normalise layer used to fold U+FF01–U+FF5E and all
        // curly quotes on every pass, silently rewriting ordinary prose on
        // every surface. Only a separator directly after a credential name
        // is folded now.
        let home = Path::new("/definitely-not-the-home");
        let prose = [
            "He said “hello” and don’t stop — really…",
            "简体中文、，。！？；：（）《》",
            "全角記号：ＡＢＣ－ＸＹＺ，！？",
            "価格：100円！重要",
            "ok 👍 done 🎉 shipped 🚀",
            "CJK comma 、 and full stop 。",
            "مرحبا بالعالم",
            "price＝100 and ratio：0.5",
        ];
        for raw in prose {
            assert_eq!(redact_secrets(raw), raw, "redact_secrets rewrote {raw}");
            assert_eq!(
                scrub_external_preview(home, raw, 1 << 20),
                raw,
                "preview rewrote {raw}"
            );
            assert_eq!(
                sanitize_error_detail(home, raw, 4096),
                raw,
                "detail rewrote {raw}"
            );
        }
    }
}
