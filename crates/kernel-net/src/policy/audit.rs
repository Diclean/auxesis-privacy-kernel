//! The `web.fetch` audit row, and the SHA-256 hashing that keeps text out of it.

use serde::Serialize;

/// Lowercase hex SHA-256 of `bytes`.
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One `web.fetch` audit row: host + hashes, never the query/URL text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebFetchEvent {
    /// Host that was (or would have been) reached.
    pub host: String,
    /// SHA-256 of the query string, when the URL had one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_sha256: Option<String>,
    /// SHA-256 of the full URL. Set only on a refused-redirect-hop row, which
    /// names the hop host so the owner can see where a redirect tried to go.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_sha256: Option<String>,
    /// Bytes of rendered text returned (0 when nothing was fetched).
    pub bytes: usize,
    /// Outcome status (`ok`, `http_status`, `refused`, `asked`, `denied`,
    /// `budget_denied`, `redirect_refused`, `error`).
    pub status: String,
    /// Effective `[web] mode`.
    pub mode: String,
    /// Gate decision (`allow` / `ask` / `deny`) and its reason.
    pub outcome: String,
    /// True when the conversation carried untrusted content.
    pub tainted: bool,
    /// True when the turn had read private owner data.
    pub carries_private_data: bool,
}

impl WebFetchEvent {
    /// Serialize the row for `store.log_event("web.fetch", …)`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    #[test]
    fn old_version_vector_web_audit() {
        assert_eq!(
            sha256_hex(b"https://example.test/search?q=synthetic"),
            "781303a58d48e88a243b33408f1757a658c221c5aa6511812e69f4d06c31d569"
        );
    }
}
