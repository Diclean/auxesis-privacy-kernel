//! Tests for credential-name classification.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_shaped_values_survive() {
        // B3-07: a UUID under an `*_id` name, an epoch under `token`, a
        // CamelCase type name under `password`.
        let uuid = "7f2c1b3a-4d5e-6f70-8192-a3b4c5d6e7f8";
        for raw in [
            format!("token_id: {uuid}"),
            format!("session_id={uuid}"),
            format!("access_key_id: {uuid}"),
            "token: 1699999999999".to_string(),
            "password: MySecretValue123".to_string(),
        ] {
            assert_eq!(redact_secrets(&raw), raw, "mangled {raw}");
        }
        // The same shapes under a credential name still redact.
        let clean = redact_secrets("password: 7f2c1b3a-4d5e-6f70-8192-a3b4c5d6e7f8");
        assert!(clean.contains("<redacted>"), "{clean}");
    }

    #[test]
    fn separator_lookalikes_fold_only_next_to_a_credential_name() {
        // B3-04 stays fixed (all four aliases) while B5-07's whole-block
        // rewrite is gone.
        assert_eq!(
            redact_secrets("api_key＝CANARY_E5FULL01"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key：CANARY_E5FULL02"),
            "api_key:<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key﹕CANARY_E5FULL03"),
            "api_key:<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key﹦CANARY_E5FULL04"),
            "api_key=<redacted>"
        );
        assert_eq!(redact_secrets("price＝100"), "price＝100");
        assert_eq!(redact_secrets("全角記号：ＡＢＣ"), "全角記号：ＡＢＣ");
    }
}
