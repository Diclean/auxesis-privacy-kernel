//! Secrets named by the line they sit on: passwords, DSNs, CLI flags.

use super::helpers::masked;

#[test]
fn name_assigned_secrets_and_authorization_values_are_masked() {
    for (text, value) in [
        (
            "MISTRAL_API_KEY=FAKEKEY0123456789abcdefGHIJ",
            "FAKEKEY0123456789abcdefGHIJ",
        ),
        (
            "\"client_secret\": \"FAKEKEY0123456789abcdef\"",
            "FAKEKEY0123456789abcdef",
        ),
        ("password: hunter2hunter2", "hunter2hunter2"),
        (
            "Authorization: Bearer FAKEKEY0123456789abcdefGHIJ",
            "FAKEKEY0123456789abcdefGHIJ",
        ),
        (
            "Authorization: Basic RkFLRUtFWTpGQUtFS0VZMDEyMw==",
            "RkFLRUtFWTpGQUtFS0VZMDEyMw==",
        ),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(
            out.contains("SECRET_"),
            "no SECRET token for {value}: {out}"
        );
    }
}

#[test]
fn password_keys_in_six_languages_mask_their_value() {
    // A password key takes `:`, `=` or the fullwidth `：` after it, with spaces
    // or tabs around it. A password value needs four characters; a short value
    // is not one.
    for (text, value) in [
        ("mot de passe : Tr0ub4dor&3x", "Tr0ub4dor&3x"),
        ("mot_de_passe=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("motdepasse: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("mdp: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("jelszó: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("jelszo: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("geslo: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("wagwoord: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("密码：Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("密碼=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("口令: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("pwd=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("passwd: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("passphrase = Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("DB_PASS=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("DB_PWD=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("password: hunter2", "hunter2"),
        ("pwd=abcd", "abcd"),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {text}: {out}");
    }
}

#[test]
fn password_words_in_prose_and_short_values_stay_clear() {
    for text in [
        "the password policy requires 12 characters",
        "mot de passe oublié ?",
        "Kérem a jelszó visszaállítását",
        "geslo je pozabljeno",
        "忘记密码了",
        "bypass: Fk3jQ9xZ2m",
        "pwd=abc",
    ] {
        let out = masked(text);
        assert!(
            !out.contains("SECRET_"),
            "over-masked as a secret: {text} -> {out}"
        );
    }
}

#[test]
fn name_assigned_values_mask_for_every_key_shape_and_value_form() {
    // The key is any segment of a name (SECRET_KEY, secretKey, db.password, STRIPE_SECRET),
    // and the value is quoted, a block scalar, or an unquoted run that may hold `:`, `=`, `;`, `,`.
    for (text, value) in [
        ("password: Pass:w0rd99", "Pass:w0rd99"),
        ("DB_PASSWORD=Summer=2024", "Summer=2024"),
        (
            "password: \"correct horse battery staple\"",
            "correct horse battery staple",
        ),
        ("DB_PASSWORD=\"Fk3j;Q9xZ2mA\"", "Fk3j;Q9xZ2mA"),
        ("password: \"Fk3j,Q9xZ2mAA\"", "Fk3j,Q9xZ2mAA"),
        ("password = Fk3j;Q9xZ2m", "Fk3j;Q9xZ2m"),
        ("password: |\n  Fk3jQ9xZ2mAA", "Fk3jQ9xZ2mAA"),
        ("token: >-\n  Fk3jQ9xZ2mP7vB4nX", "Fk3jQ9xZ2mP7vB4nX"),
        (
            "SECRET_KEY=django-insecure-Fk3jQ9xZ2m",
            "django-insecure-Fk3jQ9xZ2m",
        ),
        (
            "\"secretKey\": \"Fk3jQ9xZ2mP7vB4nX8cV\"",
            "Fk3jQ9xZ2mP7vB4nX8cV",
        ),
        ("SECRET_KEY_BASE=9f8e7d6c5b4a3210", "9f8e7d6c5b4a3210"),
        ("PRIVATE_KEY=Fk3jQ9xZ2mP7vB4n", "Fk3jQ9xZ2mP7vB4n"),
        ("ENCRYPTION_KEY=Fk3jQ9xZ2mP7vB4n", "Fk3jQ9xZ2mP7vB4n"),
        ("MASTER_KEY=Fk3jQ9xZ2mP7vB4n", "Fk3jQ9xZ2mP7vB4n"),
        (
            "APP_KEY=base64:Fk3jQ9xZ2mP7vB4n=",
            "base64:Fk3jQ9xZ2mP7vB4n=",
        ),
        ("STRIPE_SECRET=Fk3jQ9xZ2mP7vB4n", "Fk3jQ9xZ2mP7vB4n"),
        ("db.password=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("mdp: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("password: hunter2", "hunter2"),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(
            out.contains("SECRET_"),
            "no SECRET token for {text:?}: {out}"
        );
    }
    // The key stays in clear: only the value is the secret.
    let out = masked("{\"password\": \"Fk3jQ9xZ2mAA\"}");
    assert!(
        out.contains("\"password\""),
        "the JSON key was masked: {out}"
    );
}

#[test]
fn a_natural_language_key_masks_the_rest_of_its_line_as_an_accepted_over_mask() {
    for text in [
        "The password: never share it with anyone.",
        "Le mot de passe : changez-le tous les mois.",
        "A jelszó: legalább nyolc karakter legyen.",
        "Geslo: vsaj osem znakov.",
        "Die wagwoord: moet sterk wees.",
    ] {
        let out = masked(text);
        assert!(
            out.contains("SECRET_"),
            "a natural-language key is an accepted over-mask, so it masks: {text} -> {out}"
        );
    }
}

#[test]
fn a_dsn_password_masks_as_secret_for_every_host_and_user_form() {
    for (text, value) in [
        (
            "DATABASE_URL=postgres://admin:S3cr3tPassw0rd@localhost:5432/app",
            "S3cr3tPassw0rd",
        ),
        ("redis://:R3disPassw0rd@redis:6379/0", "R3disPassw0rd"),
        ("mysql://app:Fk3jQ9xZ2mP7@10.0.0.5:3306/db", "Fk3jQ9xZ2mP7"),
        (
            "https://svc:Fk3jQ9xZ2mP7@api.example.invalid/v1",
            "Fk3jQ9xZ2mP7",
        ),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {text}: {out}");
        assert!(
            !out.contains("EMAIL_"),
            "the DSN was read as an e-mail: {out}"
        );
    }
}

#[test]
fn r6_name_forms_mask_the_rest_of_the_line_in_every_shape() {
    // Each key is a secret-class name; the value is the rest of its line, whatever
    // the separator or the quoting.
    for (text, value) in [
        ("MAIL_PASSWORD=my mail pass 2024", "my mail pass 2024"),
        (
            "password = correct horse battery staple",
            "correct horse battery staple",
        ),
        ("spring.datasource.password=Hunter2 xyz", "Hunter2 xyz"),
        ("password: P@ss w0rd 2024", "P@ss w0rd 2024"),
        ("DB_PASSWORD: hunter rabbit", "hunter rabbit"),
        (
            "Wifi password: sunshine see you at 8",
            "sunshine see you at 8",
        ),
        ("The guest password: letmein, thanks!", "letmein, thanks!"),
        ("password: &dbpw Hunter2xyz", "&dbpw Hunter2xyz"),
        ("password: !!str Hunter2xyz", "!!str Hunter2xyz"),
        ("password=it's-a-long-secret", "it's-a-long-secret"),
        ("password=Hun'ter2xyz", "Hun'ter2xyz"),
        ("password=Hunter\"2xyzABC", "Hunter\"2xyzABC"),
        ("password=<Hunter2xyz>", "Hunter2xyz"),
        ("password={Hunter2xyz}", "Hunter2xyz"),
        ("password: 'it''s Hunter2xyz'", "Hunter2xyz"),
        ("const token = `Fk3jQ9xZ2mP7vB4n`;", "Fk3jQ9xZ2mP7vB4n"),
        ("password = r\"Hunter2xyz\"", "Hunter2xyz"),
        ("password := \"Hunter2xyz\"", "Hunter2xyz"),
        ("'password' => 'Hunter2xyz'", "Hunter2xyz"),
        ("- name: DB_PASSWORD\n  value: Hunter2xyz", "Hunter2xyz"),
        ("<password>Hunter2xyz</password>", "Hunter2xyz"),
        ("--password Hunter2xyz", "Hunter2xyz"),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(
            out.contains("SECRET_"),
            "no SECRET token for {text:?}: {out}"
        );
    }
}

#[test]
fn a_k8s_secret_name_keeps_its_name_and_masks_its_value() {
    let out = masked("- name: DB_PASSWORD\n  value: Hunter2xyz");
    assert!(
        out.contains("DB_PASSWORD"),
        "the k8s env name was masked: {out}"
    );
    assert!(
        !out.contains("Hunter2xyz"),
        "the k8s value left in clear: {out}"
    );
}

#[test]
fn a_quoted_command_line_secret_with_spaces_is_masked_whole() {
    // A CLI value that opens with a quote runs to its matching closing quote.
    for (text, value) in [
        (
            "psql --password \"correct horse battery\" -h db",
            "correct horse battery",
        ),
        (
            "x --api-key 'FAKEkey 0123 4567' --verbose",
            "FAKEkey 0123 4567",
        ),
    ] {
        let out = masked(text);
        // Each word of the value, so a partial mask is caught too.
        for word in value.split_whitespace() {
            assert!(!out.contains(word), "{word} left in clear: {out}");
        }
        assert!(
            out.contains("SECRET_"),
            "no SECRET token for {text:?}: {out}"
        );
    }
}

#[test]
fn an_unquoted_value_stops_before_the_next_assignment_or_ampersand() {
    // The value ends at `&`, or at a blank followed by another `key=`, `key:`, `-e`
    // or `--flag`; a value with no such blank takes the whole line.
    // K-SECRET-TAIL-4 over-mask: a one-line value now runs to the line end,
    // so the next assignment is masked too; only the secret is pinned.
    let out = masked("password=Fk3jQ9xZ2m user=alice");
    assert!(
        !out.contains("Fk3jQ9xZ2m"),
        "the password left in clear: {out}"
    );
    let out = masked("token=FAKEtok12345&p0=v0");
    assert!(
        !out.contains("FAKEtok12345"),
        "the token left in clear: {out}"
    );
}

#[test]
fn an_ampersand_inside_a_password_masks_the_whole_value() {
    // `&` ends a value only before a query parameter (`&name=`). In a password it is
    // a character: the whole value is the secret, every piece of it.
    for (text, value) in [
        ("DB_PASSWORD=Xk9&mP2q!z", "Xk9&mP2q!z"),
        ("export DB_PASSWORD=Pa&ss&w0rd", "Pa&ss&w0rd"),
        ("spring.datasource.password=Rt5&wQ8zLm2N", "Rt5&wQ8zLm2N"),
        ("password: x8&Lq2PmZ7vR9tK3", "x8&Lq2PmZ7vR9tK3"),
        ("DB_PASSWORD=Kx7mQ2&pL9vR4tZ8", "Kx7mQ2&pL9vR4tZ8"),
        ("password: Tr0ub4dor&3", "Tr0ub4dor&3"),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        for piece in value.split('&').filter(|piece| piece.len() >= 3) {
            assert!(!out.contains(piece), "{piece} left in clear: {out}");
        }
        assert!(
            out.contains("SECRET_"),
            "no SECRET token for {text:?}: {out}"
        );
    }
}

#[test]
fn base64_padding_after_a_blank_stays_inside_the_value() {
    // A word followed by `==` is base64 padding, not the next assignment.
    for (text, padded) in [
        (
            "AUTH_TOKEN=Basic dXNlcjpwYXNzd29yZA==",
            "dXNlcjpwYXNzd29yZA",
        ),
        ("secret: Bearer FAKEtok3nAbc==", "FAKEtok3nAbc"),
    ] {
        let out = masked(text);
        assert!(!out.contains(padded), "{padded} left in clear: {out}");
        assert!(!out.contains("=="), "the padding left in clear: {out}");
    }
}

#[test]
fn a_quoted_value_spanning_lines_masks_through_its_closing_quote() {
    let out = masked("password=\"line one\nline two secret\"");
    for word in ["line", "one", "two"] {
        assert!(!out.contains(word), "{word} left in clear: {out}");
    }
}

#[test]
fn an_unclosed_cli_quote_masks_the_rest_of_the_line() {
    let out = masked("psql --password \"correct horse battery -h db");
    for word in ["correct", "horse", "battery"] {
        assert!(!out.contains(word), "{word} left in clear: {out}");
    }
}
