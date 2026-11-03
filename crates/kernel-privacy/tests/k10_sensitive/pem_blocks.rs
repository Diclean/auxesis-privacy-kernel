//! Private key blocks and the AWS keys that arrive by name.

use super::helpers::{assert_no_window_in_clear, masked};

#[test]
fn private_key_blocks_are_masked_whole() {
    let body = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz0123456789ABCDEFGH";
    for kind in [
        "OPENSSH PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
        "PRIVATE KEY",
    ] {
        let begin = format!("-----BEGIN {kind}-----");
        let end = format!("-----END {kind}-----");
        let text = format!("config\n{begin}\n{body}\n{body}\n{end}\nafter");
        let out = masked(&text);
        assert!(!out.contains("BEGIN"), "{kind}: header in clear: {out}");
        assert_no_window_in_clear(&out, body);
        assert!(out.contains("SECRET_"), "{kind}: no SECRET token: {out}");
    }
}

#[test]
fn aws_secret_access_keys_are_masked_by_their_key_name() {
    let value = concat!("FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE", "");
    for text in [
        format!("AWS_SECRET_ACCESS_KEY={value}"),
        format!("aws_secret_access_key = {value}"),
        format!("\"aws_secret_access_key\": \"{value}\""),
        format!("aws_secret_access_key: {value}"),
    ] {
        let out = masked(&text);
        assert!(!out.contains(value), "value left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token: {out}");
    }
}

#[test]
fn aws_secret_keys_by_name_in_every_format_are_masked() {
    let value = "FAKE-KEY_0123456789/abcdefGHIJKLmnopqrstuvwxyz0123";
    for text in [
        format!("{{\"SecretAccessKey\": \"{value}\"}}"),
        format!("secret_access_key = \"{value}\""),
        format!("AWS_SECRET_KEY={value}"),
        format!("aws_secret_access_key: >\n  {value}\n"),
        format!("aws_secret_access_key = {}\n{}", &value[..20], &value[20..]),
        format!("aws_session_token = {value}"),
    ] {
        let out = masked(&text);
        assert_no_window_in_clear(&out, &value[..20]);
        assert_no_window_in_clear(&out, &value[20..]);
        assert!(out.contains("SECRET_"), "no SECRET token: {text} -> {out}");
    }
}

#[test]
fn headerless_pem_bodies_and_smart_dashes_and_ppk_are_masked() {
    let body = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP";
    let line_one = format!("MII{}", &body[..61]);
    let line_two = &body[..64];
    let line_three = &body[64 - 64..64];
    let text = format!("config\n{line_one}\n{line_two}\n{line_three}\nend");
    let out = masked(&text);
    assert!(
        !out.contains("MII"),
        "headerless PEM header in clear: {out}"
    );
    assert_no_window_in_clear(&out, line_two);
    let dashes = "\u{2013}\u{2013}\u{2013}\u{2013}\u{2013}BEGIN PRIVATE KEY\u{2013}\u{2013}\u{2013}\u{2013}\u{2013}\n{}\n\u{2014}\u{2014}\u{2014}\u{2014}\u{2014}END PRIVATE KEY\u{2014}\u{2014}\u{2014}\u{2014}\u{2014}";
    let out = masked(&dashes.replace("{}", body));
    assert!(
        !out.contains("BEGIN") && !out.contains("END PRIVATE"),
        "smart-dash PEM in clear: {out}"
    );
    assert_no_window_in_clear(&out, body);
    let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: fake\nPublic-Lines: 2\nAAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEY0123456789abcdefGHIJKLmnopqrs\nPrivate-Lines: 1\nAAAAIFAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz0123456789ABCD\nPrivate-MAC: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    let out = masked(ppk);
    assert_no_window_in_clear(&out, "AAAAIFAKEKEY0123456789abcdef");
    assert!(
        !out.contains("Private-MAC: 0123456789"),
        "PuTTY MAC in clear: {out}"
    );
}
