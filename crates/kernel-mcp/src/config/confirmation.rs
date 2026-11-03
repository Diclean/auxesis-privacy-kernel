//! The keyed confirmation digest that binds one server to one exact launch.

use std::path::Path;

use super::{McpDataClass, McpServerConfig};

/// Bind one confirmation to one exact launch **and** to a daemon-held secret.
///
/// The command is canonicalised (symlinks resolved) where the path exists, so
/// a symlink retargeted after confirmation changes the digest and invalidates
/// it. Arguments are hashed verbatim, in order; env names are sorted and
/// deduplicated; the agent→tool allowlist is hashed sorted (item 7), so widening
/// an agent's tools invalidates the confirmation too. A non-empty `secret` keys
/// the digest, so the value cannot be reproduced from the config file alone.
/// The binary's SHA-256 is recomputed here, so a swapped binary invalidates the
/// confirmation at spawn time too.
pub(super) fn confirmation_digest(
    secret: &[u8],
    server: &McpServerConfig,
    verified_sha: Option<&str>,
) -> Option<String> {
    if secret.is_empty() {
        // Item 5: no daemon key, no confirmation — never fall back to an
        // unkeyed digest a hand edit could reproduce.
        return None;
    }
    let command = server.command.as_deref()?;
    let canonical = std::fs::canonicalize(command)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| command.to_owned());
    let mut hasher = blake3::Hasher::new_keyed(blake3::hash(secret).as_bytes());
    hasher.update(canonical.as_bytes());
    hasher.update(&[0u8]);
    for arg in &server.args {
        hasher.update(arg.as_bytes());
        hasher.update(&[0u8]);
    }
    hasher.update(&[1u8]);
    let mut names: Vec<&str> = server.env.iter().map(String::as_str).collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        hasher.update(name.as_bytes());
        hasher.update(&[0u8]);
    }
    hasher.update(&[2u8]);
    hasher.update(if server.network { b"net=1" } else { b"net=0" });
    hasher.update(&[0u8]);
    hasher.update(match server.data_class {
        McpDataClass::Public => &b"class=public"[..],
        McpDataClass::Sensitive => &b"class=sensitive"[..],
    });
    hasher.update(&[0u8]);
    hasher.update(server.transport.as_str().as_bytes());
    hasher.update(&[0u8]);
    // Item 7: the per-agent tools allowlist is part of the confirmed launch. A
    // `BTreeMap` iterates in key order, so the digest is deterministic.
    hasher.update(&[3u8]);
    for (agent, tools) in &server.agents {
        hasher.update(agent.as_bytes());
        hasher.update(&[0u8]);
        for tool in tools {
            hasher.update(tool.as_bytes());
            hasher.update(&[0u8]);
        }
        hasher.update(&[1u8]);
    }
    hasher.update(&[4u8]);
    let sha = match verified_sha {
        Some(sha) => sha.to_ascii_lowercase(),
        None => binary_sha256(Path::new(&canonical)),
    };
    hasher.update(sha.as_bytes());
    Some(hasher.finalize().to_hex().to_string())
}

/// SHA-256 of the file at `path`, streamed so a large binary is never held in
/// memory. An unreadable path hashes to a fixed marker so a missing binary can
/// still be confirmed (and then fails at spawn with its own reason).
pub fn binary_sha256(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return "unavailable".to_owned();
    };
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => digest.update(&buffer[..read]),
            Err(_) => return "unavailable".to_owned(),
        }
    }
    let mut hex = String::with_capacity(64);
    for byte in digest.finalize() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_util::shared::args;
    use crate::config::McpTransport;

    #[test]
    fn confirmation_covers_the_whole_launch_and_needs_the_daemon_key() {
        let server = McpServerConfig {
            id: "plain".into(),
            catalog_id: None,
            data_class: McpDataClass::Sensitive,
            stdio_confirmed: true,
            stdio_confirmation: None,
            network: false,
            transport: McpTransport::Stdio,
            url: None,
            command: Some("/usr/local/bin/ripgrep".into()),
            args: args(&["--stdio"]),
            env: vec![],
            enabled: true,
            agents: Default::default(),
        };
        let secret = b"daemon-token";
        // Item 5: without the daemon key there is no binding at all, so a bare
        // bool or a plain hash is never confirmation.
        assert!(server.confirmation_binding(b"").is_none());
        assert!(!server.stdio_is_confirmed_with(b""));
        let mut hand_edited = server.clone();
        hand_edited.stdio_confirmation = Some("any-plain-value".into());
        assert!(!hand_edited.stdio_is_confirmed_with(b""));
        assert!(
            !server.stdio_is_confirmed_with(secret),
            "no hash stored yet"
        );

        // Item 4: every field of the launch spec is covered.
        let mut confirmed = server.clone();
        confirmed.stdio_confirmation = server.confirmation_binding(secret);
        assert!(confirmed.stdio_is_confirmed_with(secret));
        let mutators: [fn(&mut McpServerConfig); 7] = [
            |s| s.args = args(&["--stdio", "--quiet"]),
            |s| s.env = vec!["DATAGOUV_KEY".into()],
            |s| s.command = Some("/usr/local/bin/other".into()),
            |s| s.network = true,
            |s| s.data_class = McpDataClass::Public,
            |s| s.transport = McpTransport::Http,
            // Item 7: widening an agent's tools invalidates the confirmation.
            |s| {
                s.agents.insert("main".into(), vec!["tool".into()]);
            },
        ];
        for mutate in mutators {
            let mut changed = confirmed.clone();
            mutate(&mut changed);
            assert!(
                !changed.stdio_is_confirmed_with(secret),
                "a changed launch spec must invalidate the confirmation"
            );
        }

        // Item 4: a swapped binary invalidates the confirmation.
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("server");
        std::fs::write(&bin, b"one").unwrap();
        let mut file_server = server.clone();
        file_server.command = Some(bin.to_string_lossy().into_owned());
        let mut file_confirmed = file_server.clone();
        file_confirmed.stdio_confirmation = file_server.confirmation_binding(secret);
        assert!(file_confirmed.stdio_is_confirmed_with(secret));
        std::fs::write(&bin, b"two").unwrap();
        assert!(
            !file_confirmed.stdio_is_confirmed_with(secret),
            "a binary swapped after confirmation must be refused at spawn"
        );

        // A binding built from a verified (catalog) checksum equals the
        // file-read binding when the file matches, and a swap after the
        // check is still refused at spawn.
        std::fs::write(&bin, b"pinned").unwrap();
        let pinned_sha = binary_sha256(&bin);
        assert_eq!(
            file_server.confirmation_binding_for_sha(secret, &pinned_sha.to_ascii_uppercase()),
            file_server.confirmation_binding(secret)
        );
        let mut sha_confirmed = file_server.clone();
        sha_confirmed.stdio_confirmation =
            file_server.confirmation_binding_for_sha(secret, &pinned_sha);
        assert!(sha_confirmed.stdio_is_confirmed_with(secret));
        std::fs::write(&bin, b"replacement").unwrap();
        assert!(
            !sha_confirmed.stdio_is_confirmed_with(secret),
            "a binary swapped after the catalog check must be refused at spawn"
        );
    }
}
