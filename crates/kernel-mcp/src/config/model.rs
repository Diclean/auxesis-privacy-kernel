//! The `mcp.toml` data model: types, bounds and the `McpConfig` read/write API.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use toml_edit::DocumentMut;

use super::document::{document_server_entries, entry_id, entry_transport, validate_server_entry};
use super::echo::shown;
use super::rewrite::{edit_server_entries, server_to_table};
use super::{MAX_MCP_CONFIG_BYTES, MAX_MCP_SERVERS};

/// Transport one configured server speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpTransport {
    /// Streamable HTTP endpoint.
    Http,
    /// Local child process speaking newline-delimited JSON-RPC.
    Stdio,
}

/// Privacy classification of an MCP server's source data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum McpDataClass {
    Public,
    #[default]
    Sensitive,
}

impl McpTransport {
    /// Lowercase config label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Stdio => "stdio",
        }
    }
}

/// One `[[server]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerConfig {
    /// User-chosen id, `[a-z0-9-]{1,32}` and unique in the file.
    pub id: String,
    /// Optional reference to `catalog/mcp-servers.toml`; informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_id: Option<String>,
    /// Missing legacy values are conservatively treated as sensitive.
    #[serde(default)]
    pub data_class: McpDataClass,
    /// Explicit owner confirmation for package-runner or other gated launchers.
    ///
    /// A hand-edited `true` is **not** enough on its own: the flag is only
    /// honoured together with [`McpServerConfig::stdio_confirmation`], a hash
    /// of `(canonical command, args, env names)` written by the daemon's
    /// confirm endpoint. Any change to those three invalidates it.
    #[serde(default)]
    pub stdio_confirmed: bool,
    /// Hash binding the confirmation to one exact launch
    /// (`canonical command path, args, env names`). `None` means the server has
    /// never been confirmed by the daemon, whatever `stdio_confirmed` says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdio_confirmation: Option<String>,
    /// The owner's approval of the whole install preview, keyed by the
    /// daemon token. `None` means never approved; an enabled server without a
    /// matching record never starts (one-approval install).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
    /// Whether the server needs network access. A sandboxed stdio child gets
    /// sockets only when this is set; the default denies all sockets.
    #[serde(default)]
    pub network: bool,
    /// Transport to use.
    pub transport: McpTransport,
    /// `http`: endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// `stdio`: absolute path to the executable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// `stdio`: arguments passed verbatim (never through a shell).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Environment variable **names** read from `~/.auxesis/.env` and injected
    /// at launch (stdio). Names only; no value is ever stored here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Whether the daemon starts this server. Nothing is enabled by default.
    #[serde(default)]
    pub enabled: bool,
    /// `[server.agents]`: agent -> the remote tool names that agent may see. An agent
    /// with no entry sees nothing from this server. Read from the legacy
    /// `[server.dots]` table too.
    #[serde(
        default,
        skip_serializing_if = "std::collections::BTreeMap::is_empty",
        alias = "dots"
    )]
    pub agents: std::collections::BTreeMap<String, Vec<String>>,
}

/// One `[[server]]` entry that could not even be deserialized.
///
/// It is kept apart from the valid servers so one bad entry never drops the
/// rest of the file (item 6). `id` is best-effort (the raw `id` when the entry
/// is a table carrying one) and `reason` is a stable, content-free label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedServer {
    /// Best-effort id, or `"<entry>"` when the entry carried none.
    pub id: String,
    /// Transport when the entry named a valid one.
    pub transport: Option<McpTransport>,
    /// Stable, content-free quarantine label.
    pub reason: &'static str,
    /// Best-effort TOML rendering of the entry, for display and diagnostics.
    ///
    /// Rewrites no longer use this: the whole document is parsed with
    /// `toml_edit` and edited in place, so the entry (and every comment around
    /// it) is preserved verbatim by construction. This stays for callers that
    /// want to show the owner what was rejected.
    pub raw: String,
}

/// The whole `mcp.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpConfig {
    /// Every declared server, in file order.
    #[serde(default)]
    pub server: Vec<McpServerConfig>,
    /// Entries that failed to deserialize, kept so the API/UI can report them.
    ///
    /// Never serialized back on its own: the source document already holds
    /// them, and a rewrite leaves every quarantined entry untouched in place.
    #[serde(skip)]
    pub quarantined: Vec<QuarantinedServer>,
    /// The exact text this configuration was parsed from.
    ///
    /// Keep it so a rewrite (confirm, revoke, enable, delete, add) can edit the
    /// parsed `toml_edit` document in place: comments, formatting, ordering and
    /// quarantined entries survive byte-for-byte. Empty for a configuration
    /// built in memory, which then serializes from scratch.
    #[serde(skip)]
    source: String,
}

impl McpConfig {
    /// Parse `text`, naming `source` in any error.
    ///
    /// The document is parsed once with `toml_edit` (the exact text is kept for
    /// later in-place rewrites). The top-level structure is then checked; each
    /// `server` entry is deserialized **on its own**, so an unknown transport,
    /// an unknown key, a missing transport or a bad `data_class` quarantines
    /// only that entry and every other server still loads (item 6). A
    /// whole-file syntax error is still an error.
    ///
    /// Unknown top-level keys are refused. A duplicate id quarantines **every**
    /// entry that carries it (item 6): when one of them is already invalid, the
    /// good twin is quarantined too, so deleting it can never promote the
    /// hidden duplicate; both stay quarantined until the owner fixes the file.
    pub fn parse(source: &str, text: &str) -> Result<Self, McpConfigError> {
        if text.len() as u64 > MAX_MCP_CONFIG_BYTES {
            return Err(McpConfigError::TooLarge {
                path: source.to_owned(),
                size: text.len() as u64,
            });
        }
        let document = text
            .parse::<DocumentMut>()
            .map_err(|err| McpConfigError::Parse {
                path: source.to_owned(),
                message: kernel_core::describe_toml_error("", text, err.span(), err.message()),
            })?;
        // An unknown key is never quoted: it came from the file.
        if document.as_table().iter().any(|(key, _)| key != "server") {
            return Err(invalid(
                "unknown top-level key (only [[server]] is allowed)",
            ));
        }
        let entries = document_server_entries(&document)?;
        let mut config = Self {
            source: text.to_owned(),
            ..Self::default()
        };
        // Best-effort id of every entry, so a duplicated id (whether or not one
        // twin is otherwise valid) quarantines all of them as `duplicate_id`.
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for entry in &entries {
            if let Some(id) = entry_id(&entry.value) {
                *counts.entry(id).or_insert(0) += 1;
            }
        }
        for (index, entry) in entries.iter().enumerate() {
            let id = entry_id(&entry.value);
            let transport = entry_transport(&entry.value);
            let duplicated = id
                .as_deref()
                .is_some_and(|id| counts.get(id).copied().unwrap_or(0) > 1);
            let outcome = if duplicated {
                Err("duplicate_id")
            } else {
                validate_server_entry(&entry.value)
            };
            match outcome {
                Ok(server) => config.server.push(server),
                Err(reason) => config.quarantined.push(QuarantinedServer {
                    id: id.unwrap_or_else(|| format!("<entry {}>", index + 1)),
                    transport,
                    reason,
                    raw: entry.raw.clone(),
                }),
            }
        }
        if config.server.len() > MAX_MCP_SERVERS {
            for server in config.server.split_off(MAX_MCP_SERVERS) {
                let raw = format!("[[server]]\n{}", server_to_table(&server));
                config.quarantined.push(QuarantinedServer {
                    id: server.id,
                    transport: Some(server.transport),
                    reason: "too_many_servers",
                    raw,
                });
            }
        }
        Ok(config)
    }

    /// Build a configuration from an in-memory server list (no source text).
    ///
    /// A rewrite then serializes from scratch; a parsed configuration instead
    /// edits its source document in place.
    pub fn from_servers(server: Vec<McpServerConfig>) -> Self {
        Self {
            server,
            ..Self::default()
        }
    }

    /// Read `path`, validating it. A missing file is an empty configuration.
    pub fn load_from_path(path: &Path) -> Result<Self, McpConfigError> {
        match std::fs::metadata(path) {
            Ok(meta) => {
                if !meta.is_file() {
                    return Err(McpConfigError::NotRegularFile {
                        path: path.display().to_string(),
                    });
                }
                if meta.len() > MAX_MCP_CONFIG_BYTES {
                    return Err(McpConfigError::TooLarge {
                        path: path.display().to_string(),
                        size: meta.len(),
                    });
                }
                let text = std::fs::read_to_string(path)?;
                Self::parse(&path.display().to_string(), &text)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(McpConfigError::Io(err)),
        }
    }

    /// Enabled servers, in file order.
    pub fn enabled_servers(&self) -> impl Iterator<Item = &McpServerConfig> {
        self.server.iter().filter(|server| server.enabled)
    }

    /// The server with `id`, if declared.
    pub fn server(&self, id: &str) -> Option<&McpServerConfig> {
        self.server.iter().find(|server| server.id == id)
    }

    /// Whether the configuration declares nothing.
    pub fn is_empty(&self) -> bool {
        self.server.is_empty() && self.quarantined.is_empty()
    }

    /// Whole-file structural checks: server count and unique ids.
    ///
    /// A single invalid or unconfirmed server is **not** a whole-file error:
    /// it is quarantined one by one (see [`McpServerConfig::check`] and the
    /// runtime's `NeedsConfirmation`/`Quarantined` states), so every other
    /// server still loads.
    pub fn validate_structural(&self) -> Result<(), McpConfigError> {
        if self.server.len() > MAX_MCP_SERVERS {
            return Err(invalid(format!(
                "too many servers ({} > {MAX_MCP_SERVERS})",
                self.server.len()
            )));
        }
        let mut seen = BTreeSet::new();
        for server in &self.server {
            if !seen.insert(server.id.as_str()) {
                return Err(invalid(format!(
                    "duplicate server id {}",
                    shown(&server.id, "<id>")
                )));
            }
        }
        Ok(())
    }

    /// Strict validation of every server (structural checks included).
    ///
    /// Kept for callers that want one clear error; the runtime instead walks
    /// the servers and quarantines each failure in isolation.
    pub fn validate(&self) -> Result<(), McpConfigError> {
        self.validate_structural()?;
        for server in &self.server {
            server.check().map_err(|refusal| McpConfigError::Invalid {
                reason: refusal.detail,
            })?;
        }
        Ok(())
    }

    /// Serialize the configuration for writing, preserving the source document.
    ///
    /// The document parsed at load time is edited **in place** with
    /// `toml_edit`: only the tables that changed are touched, so every comment,
    /// blank line, key order, `[[ server ]]` spelling and quarantined entry
    /// stays byte-for-byte. A configuration assembled in memory (`source`
    /// empty) is written from scratch instead.
    ///
    /// Item 7: the retained source parsed once already, so a re-parse failure
    /// is a bug rather than a normal case — the rewrite is **refused** instead
    /// of silently replacing the owner's file with a from-scratch document.
    pub fn to_toml_string(&self) -> Result<String, McpConfigError> {
        let mut document: DocumentMut = if self.source.is_empty() {
            DocumentMut::new()
        } else {
            self.source
                .parse::<DocumentMut>()
                .map_err(|err| McpConfigError::Parse {
                    path: "<retained source>".to_owned(),
                    message: kernel_core::describe_toml_error(
                        "",
                        &self.source,
                        err.span(),
                        err.message(),
                    ),
                })?
        };
        edit_server_entries(&mut document, &self.server, &self.quarantined);
        Ok(document.to_string())
    }
}

/// Why an `mcp.toml` could not be used.
#[derive(Debug, thiserror::Error)]
pub enum McpConfigError {
    /// Reading the file failed.
    #[error("reading MCP configuration: {0}")]
    Io(#[from] std::io::Error),
    /// The path exists but is not a regular file.
    #[error("MCP configuration {path} is not a regular file")]
    NotRegularFile {
        /// Offending path.
        path: String,
    },
    /// The file is larger than [`MAX_MCP_CONFIG_BYTES`].
    #[error("MCP configuration {path} is unexpectedly large ({size} bytes)")]
    TooLarge {
        /// Offending path.
        path: String,
        /// Observed size.
        size: u64,
    },
    /// The TOML does not parse (unknown keys included).
    ///
    /// The message is [`kernel_core::describe_toml_error`]: a line/column and
    /// a syntax description, never the offending text.
    #[error("parsing MCP configuration at {path}: {message}")]
    Parse {
        /// Offending path or source label.
        path: String,
        /// Parser-rendered syntax error.
        message: String,
    },
    /// The TOML parsed but names something unusable.
    #[error("invalid MCP configuration: {reason}")]
    Invalid {
        /// Human-readable, secret-free reason.
        reason: String,
    },
}

pub(super) fn invalid(reason: impl Into<String>) -> McpConfigError {
    McpConfigError::Invalid {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_key_is_refused_without_quoting_it() {
        let err = McpConfig::parse("mcp.toml", "sk-abc = 1\n").unwrap_err();
        let (shown, debug) = (err.to_string(), format!("{err:?}"));
        assert!(!shown.contains("abc") && !debug.contains("abc"), "{debug}");
        assert!(shown.contains("unknown top-level key"), "{shown}");
    }

    #[test]
    fn a_parse_error_names_the_line_and_never_quotes_it() {
        let text = "[[server]]\nid = \"x\"\ntoken = \"sk-CANARY-1234567890abcdef\n";
        let err = McpConfig::parse("mcp.toml", text).unwrap_err();
        let (shown, debug) = (err.to_string(), format!("{err:?}"));
        assert!(
            !shown.contains("CANARY") && !debug.contains("CANARY"),
            "{debug}"
        );
        assert!(shown.contains("mcp.toml: line 3"), "{shown}");
    }

    #[test]
    fn per_server_failures_do_not_drop_the_whole_config() {
        let config = McpConfig::parse(
            "t",
            "[[server]]\nid = \"bad\"\ntransport = \"stdio\"\ncommand = \"relative\"\n\n\
             [[server]]\nid = \"good\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n",
        )
        .unwrap();
        assert_eq!(config.server.len(), 2);
        assert!(config.server[0].check().is_err());
        assert_eq!(
            config.server[0].check().unwrap_err().label,
            "command_refused"
        );
        assert!(config.server[1].check().is_ok());
    }

    #[test]
    fn unknown_transport_entry_is_quarantined_next_to_good_entries() {
        let config = McpConfig::parse(
            "t",
            "[[server]]\nid = \"bad\"\ntransport = \"carrier-pigeon\"\n\n\
             [[server]]\nid = \"good\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n",
        )
        .unwrap();
        assert_eq!(config.server.len(), 1, "the good entry must survive");
        assert_eq!(config.server[0].id, "good");
        assert!(config.server[0].check().is_ok());
        assert_eq!(config.quarantined.len(), 1);
        assert_eq!(config.quarantined[0].id, "bad");
        assert_eq!(config.quarantined[0].reason, "invalid_transport");
        assert!(!config.is_empty());

        let config = McpConfig::parse(
            "t",
            "[[server]]\nid = \"typo\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\nnetworkk = true\n\n\
             [[server]]\nid = \"good\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n",
        )
        .unwrap();
        assert_eq!(config.server.len(), 1);
        assert_eq!(config.quarantined.len(), 1);
        assert_eq!(config.quarantined[0].reason, "unknown_key");

        let config = McpConfig::parse(
            "t",
            "[[server]]\nid = \"no-transport\"\n\n\
             [[server]]\nid = \"bad-class\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\ndata_class = \"secret\"\n",
        )
        .unwrap();
        assert!(config.server.is_empty());
        assert_eq!(config.quarantined.len(), 2);
        assert_eq!(config.quarantined[0].reason, "missing_transport");
        assert_eq!(config.quarantined[1].reason, "invalid_data_class");
    }

    #[test]
    fn a_retained_source_that_no_longer_parses_refuses_the_rewrite() {
        // Item 7: the retained source parsed once already, so a re-parse
        // failure must refuse the write, never silently fall back to a
        // from-scratch document that would drop the owner's file.
        let mut config = McpConfig::parse(
            "mcp.toml",
            "[[server]]\nid = \"a\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n",
        )
        .unwrap();
        assert!(config.to_toml_string().is_ok());
        config.source = "[[server]]\nid = ".to_owned();
        assert!(matches!(
            config.to_toml_string(),
            Err(McpConfigError::Parse { .. })
        ));
    }

    #[test]
    fn a_duplicate_id_quarantines_both_twins_and_delete_cannot_promote_one() {
        for text in [
            // Good + bad duplicate.
            "[[server]]\nid = \"x\"\ntransport = \"http\"\nurl = \"https://a.invalid/mcp\"\n\n\
             [[server]]\nid = \"x\"\ntransport = \"carrier-pigeon\"\n",
            // Two good duplicates.
            "[[server]]\nid = \"x\"\ntransport = \"http\"\nurl = \"https://a.invalid/mcp\"\n\n\
             [[server]]\nid = \"x\"\ntransport = \"http\"\nurl = \"https://b.invalid/mcp\"\n",
        ] {
            let mut config = McpConfig::parse("mcp.toml", text).unwrap();
            assert!(config.server.is_empty(), "both twins must be quarantined");
            assert_eq!(config.quarantined.len(), 2);
            assert!(config
                .quarantined
                .iter()
                .all(|entry| entry.reason == "duplicate_id"));
            // Deleting the "good" one is a no-op: it never became a server, so
            // the hidden duplicate cannot be promoted.
            config.server.retain(|server| server.id != "x");
            let written = config.to_toml_string().unwrap();
            let reparsed = McpConfig::parse("mcp.toml", &written).unwrap();
            assert_eq!(
                reparsed.quarantined.len(),
                2,
                "both twins stay quarantined until the owner fixes the file"
            );
            assert!(reparsed.server.is_empty());
        }
    }
}
