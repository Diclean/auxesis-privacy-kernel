//! The keyed confirmation digest that binds one server to one exact launch.

use std::path::Path;

use super::digest::{hash_count, hash_field, hash_flag};
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
/// confirmation at spawn time too. A binary that cannot be **read** cannot be
/// hashed: the digest is then refused outright (no binding at all) rather than
/// binding the [`UNAVAILABLE_SHA256`] marker as if it were a hash.
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
    // v2: tagged, length-prefixed and counted, exactly like the approval
    // digest, so an args/env swap (or a tool moving between agents) invalidates
    // the confirmation instead of reusing the old bytes.
    hasher.update(b"mcp-confirmation-v2\0");
    hash_field(&mut hasher, b"command:", &canonical);
    hash_count(&mut hasher, b"args:", server.args.len());
    for arg in &server.args {
        hash_field(&mut hasher, b"arg:", arg);
    }
    let mut names: Vec<&str> = server.env.iter().map(String::as_str).collect();
    names.sort_unstable();
    names.dedup();
    hash_count(&mut hasher, b"env:", names.len());
    for name in names {
        hash_field(&mut hasher, b"env-name:", name);
    }
    hash_flag(&mut hasher, b"network:", server.network);
    hash_field(
        &mut hasher,
        b"class:",
        match server.data_class {
            McpDataClass::Public => "public",
            McpDataClass::Sensitive => "sensitive",
        },
    );
    hash_field(&mut hasher, b"transport:", server.transport.as_str());
    // Item 7: the per-agent tools allowlist is part of the confirmed launch. A
    // `BTreeMap` iterates in key order, so the digest is deterministic.
    hash_count(&mut hasher, b"agents:", server.agents.len());
    for (agent, tools) in &server.agents {
        hash_field(&mut hasher, b"agent:", agent);
        hash_count(&mut hasher, b"agent-tools:", tools.len());
        for tool in tools {
            hash_field(&mut hasher, b"tool:", tool);
        }
    }
    let sha = match verified_sha {
        Some(sha) => sha.to_ascii_lowercase(),
        None => binary_sha256(Path::new(&canonical)),
    };
    // A program that cannot be read cannot be hashed, and the marker is not a
    // hash: it never enters a digest. No binding, so no confirmation and no
    // launch (fail closed).
    if sha.eq_ignore_ascii_case(UNAVAILABLE_SHA256) {
        return None;
    }
    hash_field(&mut hasher, b"sha256:", &sha);
    Some(hasher.finalize().to_hex().to_string())
}

/// The marker [`binary_sha256`] returns for a program it cannot read.
///
/// It is **not** a hash: no digest ever binds it, so a program that cannot be
/// hashed can neither be approved nor started.
pub const UNAVAILABLE_SHA256: &str = "unavailable";

/// SHA-256 of the file at `path`, streamed so a large binary is never held in
/// memory.
///
/// An unreadable path hashes to the fixed marker [`UNAVAILABLE_SHA256`], which
/// no digest binds: a program that cannot be read cannot be hashed, so it is
/// never approved and never confirmed.
pub fn binary_sha256(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return UNAVAILABLE_SHA256.to_owned();
    };
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => digest.update(&buffer[..read]),
            Err(_) => return UNAVAILABLE_SHA256.to_owned(),
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
        // A readable program file: a program that cannot be **hashed** has no
        // binding at all (see `an_unhashable_program_is_never_approved_or_confirmed`),
        // so the launch spec below is bound over a real SHA-256.
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("ripgrep");
        std::fs::write(&bin, b"one").unwrap();
        let server = McpServerConfig {
            id: "plain".into(),
            catalog_id: None,
            data_class: McpDataClass::Sensitive,
            stdio_confirmed: true,
            stdio_confirmation: None,
            approval: None,
            network: false,
            transport: McpTransport::Stdio,
            url: None,
            command: Some(bin.to_string_lossy().into_owned()),
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
        let swap_dir = tempfile::tempdir().unwrap();
        let swap_bin = swap_dir.path().join("server");
        std::fs::write(&swap_bin, b"one").unwrap();
        let mut file_server = server.clone();
        file_server.command = Some(swap_bin.to_string_lossy().into_owned());
        let mut file_confirmed = file_server.clone();
        file_confirmed.stdio_confirmation = file_server.confirmation_binding(secret);
        assert!(file_confirmed.stdio_is_confirmed_with(secret));
        std::fs::write(&swap_bin, b"two").unwrap();
        assert!(
            !file_confirmed.stdio_is_confirmed_with(secret),
            "a binary swapped after confirmation must be refused at spawn"
        );

        // A binding built from a verified (catalog) checksum equals the
        // file-read binding when the file matches, and a swap after the
        // check is still refused at spawn.
        std::fs::write(&swap_bin, b"pinned").unwrap();
        let pinned_sha = binary_sha256(&swap_bin);
        assert_eq!(
            file_server.confirmation_binding_for_sha(secret, &pinned_sha.to_ascii_uppercase()),
            file_server.confirmation_binding(secret)
        );
        let mut sha_confirmed = file_server.clone();
        sha_confirmed.stdio_confirmation =
            file_server.confirmation_binding_for_sha(secret, &pinned_sha);
        assert!(sha_confirmed.stdio_is_confirmed_with(secret));
        std::fs::write(&swap_bin, b"replacement").unwrap();
        assert!(
            !sha_confirmed.stdio_is_confirmed_with(secret),
            "a binary swapped after the catalog check must be refused at spawn"
        );
    }

    /// The fail-open finding: a program file that cannot be **read** cannot be
    /// hashed, so it can never be approved and never started.
    #[cfg(unix)]
    #[test]
    fn an_unhashable_program_is_never_approved_or_confirmed() {
        use std::os::unix::fs::PermissionsExt;

        fn server_for(command: &str) -> McpServerConfig {
            McpServerConfig {
                id: "plain".into(),
                catalog_id: None,
                data_class: McpDataClass::Sensitive,
                stdio_confirmed: false,
                stdio_confirmation: None,
                approval: None,
                network: false,
                transport: McpTransport::Stdio,
                url: None,
                command: Some(command.to_owned()),
                args: args(&["--stdio"]),
                env: vec![],
                enabled: false,
                agents: Default::default(),
            }
        }

        let secret = b"daemon-token";
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("server");
        std::fs::write(&bin, b"program A").unwrap();
        let server = server_for(&bin.to_string_lossy());

        // A readable program is hashed and bound exactly as before.
        assert_ne!(binary_sha256(&bin), UNAVAILABLE_SHA256);
        let approval = server.approval_binding(secret, None);
        let confirmation = server.confirmation_binding(secret);
        assert!(approval.is_some());
        assert!(confirmation.is_some());
        let mut approved = server.clone();
        approved.approval = approval;
        assert!(approved.is_approved_with(secret, None));
        assert!(approved.is_install_approved(Some(secret), None));
        let mut confirmed = server.clone();
        confirmed.stdio_confirmed = true;
        confirmed.stdio_confirmation = confirmation;
        assert!(confirmed.stdio_is_confirmed_with(secret));
        assert!(confirmed.is_install_approved(Some(secret), None));

        // Execute-only: the file cannot be read, so it cannot be hashed.
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o111)).unwrap();
        assert_eq!(binary_sha256(&bin), UNAVAILABLE_SHA256);

        // No binding at all: an unreadable program is never approved.
        assert!(server.approval_binding(secret, None).is_none());
        assert!(server
            .approval_binding_for_sha(secret, None, UNAVAILABLE_SHA256)
            .is_none());
        assert!(server
            .approval_binding_for_sha(secret, None, "UNAVAILABLE")
            .is_none());
        // No binding at all: an unreadable program is never confirmed.
        assert!(server.confirmation_binding(secret).is_none());
        assert!(server
            .confirmation_binding_for_sha(secret, UNAVAILABLE_SHA256)
            .is_none());
        assert!(server
            .confirmation_binding_for_sha(secret, "Unavailable")
            .is_none());

        // Neither predicate passes, whatever the stored record says.
        let mut stored = server.clone();
        stored.stdio_confirmed = true;
        stored.stdio_confirmation = Some("any-plain-value".into());
        stored.approval = Some("any-plain-value".into());
        assert!(!stored.stdio_is_confirmed_with(secret));
        assert!(!stored.is_approved_with(secret, None));
        assert!(!stored.is_install_approved(Some(secret), None));
        // The grandfathered pre-M6-2 gate (no approval record, only an old
        // launch confirmation) refuses an unreadable program too.
        let mut legacy = server.clone();
        legacy.stdio_confirmed = true;
        legacy.stdio_confirmation = Some("any-plain-value".into());
        assert!(!legacy.is_install_approved(Some(secret), None));

        // The exploit this closes: a fail-open confirm wrote a confirmation for
        // an execute-only program (the digest was computed over the marker),
        // then a DIFFERENT execute-only program replaced it at the same path.
        // The marker is the same on both sides, so the old confirmation still
        // matched and the replacement ran.
        let mut exploit = server.clone();
        exploit.stdio_confirmed = true;
        exploit.stdio_confirmation =
            exploit.confirmation_binding_for_sha(secret, UNAVAILABLE_SHA256);
        assert!(
            exploit.stdio_confirmation.is_none(),
            "a program that cannot be hashed must never get a stored confirmation"
        );
        assert!(
            !exploit.stdio_is_confirmed_with(secret),
            "an unreadable program must never be confirmed"
        );

        // The repro: program A was confirmed while it was readable; program B
        // replaces it at the same path and cannot be read, so the old
        // confirmation never passes at spawn.
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("server");
        std::fs::write(&bin, b"program A").unwrap();
        let server = server_for(&bin.to_string_lossy());
        let mut confirmed = server.clone();
        confirmed.stdio_confirmed = true;
        confirmed.stdio_confirmation = server.confirmation_binding(secret);
        assert!(confirmed.stdio_is_confirmed_with(secret));
        std::fs::write(&bin, b"program B").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o111)).unwrap();
        assert_eq!(binary_sha256(&bin), UNAVAILABLE_SHA256);
        assert!(
            !confirmed.stdio_is_confirmed_with(secret),
            "a replacement that cannot be hashed must never be confirmed"
        );
    }
}
