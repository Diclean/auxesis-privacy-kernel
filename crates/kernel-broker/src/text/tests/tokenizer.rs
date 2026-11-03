//! Tests for the tokenizer: name/value pairs, headers, URLs, PEM blocks
//! and encoded separators.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments_keep_scanning_past_a_glued_occurrence() {
        // P1-1: the first hit of a name used to decide the whole string, so
        // a vendor-prefixed decoy (`markerapi_key`) turned the redactor off.
        let cases: &[(&str, &str)] = &[
            ("DB_PASSWORD=CANARYSECRET123", "CANARYSECRET123"),
            ("MY_SERVICE_PASSWORD=CANARYSECRET123", "CANARYSECRET123"),
            (
                "GITHUB_CANCELLATION_TOKEN=x\ntoken=CANARYSECRET123",
                "CANARYSECRET123",
            ),
            ("notatoken=1 then token=CANARYSECRET123", "CANARYSECRET123"),
            ("x-token=old and token=CANARYSECRET123", "CANARYSECRET123"),
            ("password=CANARYSECRET123", "CANARYSECRET123"),
            (
                "api_key=<redacted> markerapi_key allowed — api_key=CANARYSHOP8 markerapi_key",
                "CANARYSHOP8",
            ),
        ];
        for (raw, secret) in cases {
            let clean = redact_secrets(raw);
            assert!(!clean.contains(secret), "leaked {secret:?} in {clean:?}");
        }
    }

    #[test]
    fn colon_delimited_assignments_are_redacted_with_structure_kept() {
        // B2-01: JSON, YAML/ini and `:=` spellings of the same names.
        assert_eq!(
            redact_secrets("{\"api_key\":\"CANARYJSONKEY0001\"}"),
            "{\"api_key\":\"<redacted>\"}"
        );
        assert_eq!(
            redact_secrets("api_key: CANARYE2EYAML02"),
            "api_key: <redacted>"
        );
        assert_eq!(
            redact_secrets("token := CANARYE2EWALRUS06"),
            "token := <redacted>"
        );
        assert_eq!(
            redact_secrets("{\"AUX_KEY_DEEPSEEK\":\"CANARYE2EENV10\"}"),
            "{\"AUX_KEY_DEEPSEEK\":\"<redacted>\"}"
        );
        // Percent-encoded separators (B2-10).
        assert_eq!(
            redact_secrets("api_key%3DCANARYE2EPCT12"),
            "api_key%3D<redacted>"
        );
    }

    #[test]
    fn url_userinfo_credentials_are_redacted_and_plain_urls_survive() {
        // B2-02: any scheme, empty user, `+` schemes; host stays readable.
        assert_eq!(
            redact_secrets("postgres://app:CANARYE2EURL04@db.internal:5432/prod"),
            "postgres://<redacted>@db.internal:5432/prod"
        );
        assert_eq!(
            redact_secrets("redis://:CANARYE2EURL06@cache:6379/0"),
            "redis://<redacted>@cache:6379/0"
        );
        assert_eq!(
            redact_secrets("mongodb+srv://u:CANARYE2EURL05@cluster0/db"),
            "mongodb+srv://<redacted>@cluster0/db"
        );
        assert_eq!(
            redact_secrets("DATABASE_URL=postgres://u:CANARYE2EURL10@h/d"),
            "DATABASE_URL=<redacted>"
        );
        assert_eq!(
            redact_secrets("https://example.com/docs?page=2"),
            "https://example.com/docs?page=2"
        );
        assert_eq!(
            redact_secrets("homepage_url=https://example.com"),
            "homepage_url=https://example.com"
        );
        // B2-11: an error-body URL credential.
        assert_eq!(
            redact_secrets("base_url `\"http://CANARYE2EERR13@[\"` is not valid"),
            "base_url `\"http://<redacted>@[\"` is not valid"
        );
    }

    #[test]
    fn credential_headers_are_redacted_whole() {
        // B2-03: the header name, not only `authorization`.
        assert_eq!(
            redact_secrets("X-Api-Key: CANARYE2EHDR06ABCDEFGHIJ"),
            "X-Api-Key: <redacted>"
        );
        assert_eq!(
            redact_secrets("Proxy-Authorization: Basic Q0FOQVNZVlJFTEIzNDU2Nzg5"),
            "Proxy-Authorization: <redacted>"
        );
        assert_eq!(
            redact_secrets("Cookie: session=CANARYE2ECOOKIE07abcdefghij"),
            "Cookie: <redacted>"
        );
        assert_eq!(
            redact_secrets("X-Hub-Signature-256: sha256=CANARYE2EHDR08abcdef"),
            "X-Hub-Signature-256: <redacted>"
        );
        // Shapes gate: `none` survives, a 32-byte value does not (B2-09).
        assert_eq!(redact_secrets("Authorization: none"), "Authorization: none");
        assert_eq!(
            redact_secrets("Authorization: 0123456789abcdef0123456789abcdef"),
            "Authorization: <redacted>"
        );
        // B3-09: `Whole` is not `Shaped`. A short, low-entropy credential
        // header value is still a credential and must redact, even though
        // `looks_like_secret` would keep it. This is the pin for mutation
        // P03 (every `Whole` downgraded to `Shaped`).
        assert_eq!(redact_secrets("Cookie: sid=abc"), "Cookie: <redacted>");
        assert_eq!(redact_secrets("Set-Cookie: id=a"), "Set-Cookie: <redacted>");
        assert_eq!(redact_secrets("X-Api-Key: abc123"), "X-Api-Key: <redacted>");
        assert_eq!(
            redact_secrets("X-Goog-Api-Key: ab12"),
            "X-Goog-Api-Key: <redacted>"
        );
        assert_eq!(
            redact_secrets("X-Amz-Security-Token: short"),
            "X-Amz-Security-Token: <redacted>"
        );
    }

    #[test]
    fn multi_line_and_escaped_pairs_are_redacted() {
        // B3-01: a value on the line after the key/separator is the shape
        // `jq`, `to_string_pretty`, YAML and a shell continuation produce.
        let pretty = "{\n  \"api_key\":\n    \"CANARY_E3E_MULTI01\"\n}";
        assert_eq!(
            redact_secrets(pretty),
            "{\"api_key\":\"<redacted>\"}",
            "pretty JSON is parsed and re-serialised"
        );
        assert_eq!(
            redact_secrets("api_key:\n  CANARY_E3E_MULTI04"),
            "api_key:\n  <redacted>"
        );
        assert_eq!(
            redact_secrets("export API_KEY=\\\nCANARY_E3E_MULTI07"),
            "export API_KEY=\\\n<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key:\r\n  CANARY_E3E_MULTI05"),
            "api_key:\n  <redacted>"
        );
        // A quoted value broken over lines is one value (kills mutation P09,
        // which stops the quoted scan at the first newline).
        assert_eq!(
            redact_secrets("password: \"hidden\nCANARY_E3E_QNL01\""),
            "password: \"<redacted>\""
        );
        // B3-02: escaped quotes cannot hide a key or a value.
        assert_eq!(
            redact_secrets("{\"detail\":\"{\\\"api_key\\\":\\\"CANARYJSONKEY0001\\\"}\"}"),
            "{\"detail\":\"{\\\"api_key\\\":\\\"<redacted>\"}"
        );
        assert_eq!(
            redact_secrets("{\"password\":\"a\\\"b CANARY_E3E_ESCQ02\"}"),
            "{\"password\":\"<redacted>\"}"
        );
    }

    #[test]
    fn lookalike_separators_and_invisibles_fold_before_scanning() {
        // B3-03/B3-04: the log writer used to run the redactor without the
        // sanitiser, and fullwidth forms were never folded. Both now happen
        // inside the one entry point.
        assert_eq!(
            redact_secrets("token\u{200b}=CANARY_E3E_LOG01"),
            "token=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_\u{200b}key=CANARY_E3E_LOG02"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_\u{00ad}key=CANARY_E3E_LOG03"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key\u{00a0}=CANARY_E3E_LOG04"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key\u{1b}[0m=CANARY_E3E_LOG07"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("token=\u{202e}CANARY_E3E_LOG08"),
            "token=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key＝CANARY_E3E_UNI04"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key：CANARY_E3E_UNI05"),
            "api_key:<redacted>"
        );
    }

    #[test]
    fn cookie_jars_and_percent_urls_are_redacted() {
        // B3-05: a bare cookie jar has no `Cookie:` header name.
        assert_eq!(
            redact_secrets("session=CANARY_E3E_COOKIE09abcdefghij; Path=/; HttpOnly"),
            "session=<redacted>; Path=/; HttpOnly"
        );
        assert_eq!(
            redact_secrets("sid=CANARY_E3E_COOKIE11abcdefghijklmno"),
            "sid=<redacted>"
        );
        assert_eq!(
            redact_secrets("JSESSIONID=CANARY_E3E_COOKIE10abcdefghij"),
            "JSESSIONID=<redacted>"
        );
        // A cookie jar inside `Cookie:` keeps the entire line redacted.
        assert_eq!(
            redact_secrets("Cookie: a=1; session=CANARY_E3E_COOKIE13abcdef; Path=/"),
            "Cookie: <redacted>"
        );
        // B3-06: percent-encoded scheme separators.
        assert_eq!(
            redact_secrets("postgres%3A%2F%2Fu:CANARY_E3E_URL13@h/d"),
            "postgres%3A%2F%2F<redacted>@h/d"
        );
        assert_eq!(
            redact_secrets("postgres%3a%2f%2fu:CANARY_E3E_URL15@h/d"),
            "postgres%3a%2f%2f<redacted>@h/d"
        );
        assert_eq!(
            redact_secrets("DATABASE_URL=postgres%3A%2F%2Fu:CANARY_E3E_URL14@h/d"),
            "DATABASE_URL=<redacted>"
        );
    }

    #[test]
    fn prefix_matches_never_start_mid_word() {
        // B2-07: `task-sk-1234` used to be mangled at the `sk-` boundary.
        for raw in ["task-sk-1234", "disk-sk-usage", "risk-sk-1", "disk-usage"] {
            assert_eq!(redact_secrets(raw), raw, "mangled {raw}");
        }
        assert_eq!(
            redact_secrets("token sk-canary-abcdef123456 end"),
            "token sk-<redacted> end"
        );
    }

    #[test]
    fn code_and_hash_values_are_preserved() {
        // B2-08: six-byte assignment values used to be replaced
        // unconditionally.
        for raw in [
            "public_key_sha256 = 9f2a1b3c",
            "key = \"abcdefghijkl\"",
            "let token = parse(input);",
            "password: required",
            "token: None",
            "api_key= query parameter",
            "check_id=1234 and password=short",
        ] {
            assert_eq!(redact_secrets(raw), raw, "mangled {raw}");
        }
        // A real digest after a hash-only name is preserved too.
        let digest = "3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3";
        assert_eq!(
            redact_secrets(&format!("public_key_sha256={digest}")),
            format!("public_key_sha256={digest}")
        );
    }

    #[test]
    fn pem_labels_are_case_insensitive_and_putty_keys_are_covered() {
        // B2-06.
        let pem = "-----BEGIN private key-----\nCANARYPEM0005abcdefgh\n-----END private key-----";
        assert_eq!(
            redact_secrets(pem),
            "-----BEGIN private key-----<redacted>-----END private key-----"
        );
        let putty = format!(
            "PuTTY-User-Key-File-3: ssh-rsa\nPrivate-Lines: 2\n{}\nPrivate-MAC: x",
            "CANARYPUTTY0004abcdefgh"
        );
        let clean = redact_secrets(&putty);
        assert!(!clean.contains("CANARYPUTTY0004abcdefgh"), "{clean}");
        // A certificate is not a private key and stays readable.
        let cert = "-----BEGIN CERTIFICATE-----\nMIICcanaryCERT\n-----END CERTIFICATE-----";
        assert_eq!(redact_secrets(cert), cert);
    }

    #[test]
    fn aux_key_values_below_the_assignment_threshold_are_redacted() {
        // N02 pin (B2-12): the `AUX_KEY_` rule redacts any non-empty value,
        // independent of the generic assignment threshold and of whitespace
        // around the separator.
        assert_eq!(
            redact_secrets("export AUX_KEY_X = abcd"),
            "export AUX_KEY_X = <redacted>"
        );
        assert_eq!(redact_secrets("AUX_KEY_X=1"), "AUX_KEY_X=<redacted>");
        assert_eq!(
            redact_secrets("AUX_KEY_DEEPSEEK: CANARYE2EENV10"),
            "AUX_KEY_DEEPSEEK: <redacted>"
        );
    }

    // ---- round 5: brackets, padded keys, folded schemes, sibling pairs ----

    #[test]
    fn bracketed_values_are_redacted() {
        // B5-01: `(…)`/`<…>` are value delimiters, so the pair used to read
        // an empty value and the secret survived with no name in front of it.
        assert_eq!(
            redact_secrets("api_key=(CANARY_B5PAREN01)"),
            "api_key=(<redacted>)"
        );
        assert_eq!(
            redact_secrets("password=(mysecretpassphrase)"),
            "password=(<redacted>)"
        );
        assert_eq!(
            redact_secrets("api_key=<CANARY_B5ANGLE02>"),
            "api_key=<redacted>"
        );
        // Bracket prose without a credential name stays readable.
        assert_eq!(
            redact_secrets("the (secret) ingredient"),
            "the (secret) ingredient"
        );
        assert_eq!(redact_secrets("password=(short)"), "password=(short)");
        assert_eq!(redact_secrets("if (a) then (b)"), "if (a) then (b)");
        // The wrapper can span the line break a pretty-printer inserts.
        assert_eq!(
            redact_secrets("password=(\n  CANARY_B5WRAP03\n)"),
            "password=(\n  <redacted>\n)"
        );
    }

    #[test]
    fn folded_scheme_credentials_are_redacted() {
        // B5-04: `Bearer`/`Basic` only accepted a space or tab before the
        // value, so an obs-folded credential leaked verbatim.
        assert_eq!(
            redact_secrets("Bearer\n abcdefghijklmnopqrst"),
            "Bearer\n <redacted>"
        );
        let clean = redact_secrets("Basic\n YWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        assert!(!clean.contains("YWxhZGRpbjpvcGVuIHNlc2FtZQ"), "{clean}");
        assert!(clean.contains("<redacted>"), "{clean}");
        let clean = redact_secrets("Authorization: Bearer\r\n  CANARY_B5FOLD04abcdefghij");
        assert!(!clean.contains("CANARY_B5FOLD04abcdefghij"), "{clean}");
        // `Bearer bonds` is prose, not a credential.
        assert_eq!(
            redact_secrets("The Bearer bonds are up"),
            "The Bearer bonds are up"
        );
    }

    #[test]
    fn sibling_name_value_pairs_are_redacted() {
        // E5-01: the credential name and its value in separate entries
        // defeated both layers; tool-call dumps, MCP envelopes and
        // credential managers produce exactly these shapes.
        let cases: &[&str] = &[
            r#"{"name":"api_key","value":"CANARY_E5PAIR01"}"#,
            r#"{"key":"api_key","value":"CANARY_E5PAIR02"}"#,
            r#"{"field":"password","content":"CANARY_E5PAIR03"}"#,
            r#"{"variable":"DB_PASSWORD","val":"CANARY_E5PAIR04"}"#,
            r#"{"arguments":{"name":"api_key","value":"CANARY_E5PAIR05"}}"#,
            r#"["api_key","CANARY_E5PAIR06"]"#,
            r#"["Authorization","Bearer CANARY_E5PAIR07"]"#,
            r#"["Cookie","sid=CANARY_E5PAIR08"]"#,
        ];
        for raw in cases {
            let clean = redact_secrets(raw);
            assert!(
                !clean.contains("CANARY_E5PAIR"),
                "leaked in {clean:?} (from {raw})"
            );
        }
        // A non-credential name leaves its sibling alone.
        assert_eq!(
            redact_secrets(r#"{"name":"agent-name","value":"main"}"#),
            r#"{"name":"agent-name","value":"main"}"#
        );
        assert_eq!(redact_secrets(r#"["key","value"]"#), r#"["key","value"]"#);
    }

    #[test]
    fn environment_carriers_bracket_names_and_short_pass_names_are_redacted() {
        // E6-01: tool-call dumps use `env`/`var`/`setting`/`option`/`param`
        // as the name carrier next to a value carrier; E6-04: PHP/Rails
        // bracket query names, `DB_PASS`/`PASSWD`/`PW` and short `pass=`/
        // `pw=` query names.
        let cases: &[&str] = &[
            r#"{"env":"DB_PASSWORD","value":"CANARY_E6ENV01abcdef"}"#,
            r#"{"var":"api_key","value":"CANARY_E6VAR02abcdef"}"#,
            r#"{"setting":"password","value":"CANARY_E6SET03abcdef"}"#,
            r#"{"option":"token","value":"CANARY_E6OPT04abcdef"}"#,
            r#"{"param":"secret","value":"CANARY_E6PAR05abcdef"}"#,
            "export DB_PASS=CANARY_E6PASS06abcdef",
            "MYSQL_PASSWD=CANARY_E6PASSWD07abcdef",
            "DB_PW=CANARY_E6PW08abcdef",
            "/login?auth[token]=CANARY_E6QRY09abcdef",
            "/login?token[]=CANARY_E6QRY10abcdef",
            "/login?pass=CANARY_E6QRY11abcdef",
            "/login?pw=CANARY_E6QRY12abcdef",
        ];
        for raw in cases {
            let clean = redact_secrets(raw);
            assert!(
                clean.contains("<redacted>"),
                "no marker in {clean:?} from {raw:?}"
            );
            assert!(
                !clean.contains("CANARY_E6"),
                "leaked in {clean:?} from {raw:?}"
            );
        }
        // Ordinary text with the same words stays readable.
        assert_eq!(
            redact_secrets("the env variable overview"),
            "the env variable overview"
        );
        assert_eq!(redact_secrets("pass = required"), "pass = required");
        assert_eq!(redact_secrets("pw = 1"), "pw = 1");
        assert_eq!(redact_secrets("bypass = true"), "bypass = true");
        assert_eq!(
            redact_secrets(r#"{"env":"PATH","value":"/usr/bin"}"#),
            r#"{"env":"PATH","value":"/usr/bin"}"#
        );
    }

    #[test]
    fn json5_comments_and_percent_separators_are_transparent() {
        // B5-05/E6-03: a comment before or after the separator.
        assert_eq!(
            redact_secrets("api_key /* c */ = CANARY_E6COM01abcdef"),
            "api_key /* c */ = <redacted>"
        );
        let clean = redact_secrets(r#"{ "api_key": /* c */ "CANARY_E6COM02abcdef" }"#);
        assert!(!clean.contains("CANARY_E6COM02abcdef"), "{clean}");
        assert!(clean.contains("<redacted>"), "{clean}");
        let clean = redact_secrets("api_key: // c\n CANARY_E6COM03abcdef");
        assert!(!clean.contains("CANARY_E6COM03abcdef"), "{clean}");
        // SB6-04: percent-encoded whitespace around the separator and a
        // doubled separator.
        assert_eq!(
            redact_secrets("api_key%20=%20CANARY_E6PCT04abcdef"),
            "api_key%20=%20<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key = = CANARY_E6SEP05abcdef"),
            "api_key = = <redacted>"
        );
        // Non-credential names and protocol-relative values stay readable.
        assert_eq!(redact_secrets("price /* c */ = 12"), "price /* c */ = 12");
        assert_eq!(
            redact_secrets("homepage_url=//example.com/x"),
            "homepage_url=//example.com/x"
        );
    }

    #[test]
    fn bracketed_dash_flags_and_scheme_values_are_redacted() {
        // E6-05/E6-06: the B5-01 bracket rule now covers `curl --user`/
        // `--password` and `Bearer`/`Basic`, which used to leak verbatim.
        assert_eq!(
            redact_secrets("curl --user=(admin:CANARY_E6DASH01abcdef) https://x"),
            "curl --user=(<redacted>) https://x"
        );
        assert_eq!(
            redact_secrets("curl --password=<CANARY_E6DASH02abcdef> https://x"),
            "curl --password=<redacted> https://x"
        );
        assert_eq!(
            redact_secrets("Bearer (CANARY_E6BEAR03abcdefghij)"),
            "Bearer (<redacted>)"
        );
        assert_eq!(
            redact_secrets("Basic (<CANARY_E6BASIC04abcdefg>)"),
            "Basic (<redacted>)"
        );
        // Prose with brackets stays readable.
        assert_eq!(redact_secrets("--user (me)"), "--user (me)");
        assert_eq!(redact_secrets("Bearer (bonds)"), "Bearer (bonds)");
    }
}
