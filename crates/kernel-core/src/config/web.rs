//! Web egress settings (`[web]`) and the web-read mode.

use serde::{Deserialize, Serialize};

/// Default `[web] mode`: reads of an unseen public host are not prompted
/// until the conversation carries private data or untrusted content (W1).
pub const DEFAULT_WEB_MODE: WebMode = WebMode::OpenRead;

/// Default ports a fetch may reach. Every other port is refused.
pub const DEFAULT_WEB_PORTS: [u16; 2] = [80, 443];

/// Default redirect hops followed per fetch (the first request is not counted).
pub const DEFAULT_WEB_MAX_REDIRECTS: usize = 5;

/// Default whole-fetch byte cap (`max_bytes`), 256 KiB.
pub const DEFAULT_WEB_MAX_BYTES: usize = 256 * 1024;

/// Default whole-fetch wall-clock cap, redirects included.
pub const DEFAULT_WEB_TIMEOUT_SECS: u64 = 15;

/// Default content types the fetcher is willing to render.
pub const DEFAULT_WEB_CONTENT_TYPES: [&str; 5] = [
    "text/html",
    "text/plain",
    "application/json",
    "application/xml",
    "text/xml",
];

/// Default fetches allowed in one turn.
pub const DEFAULT_WEB_FETCHES_PER_TURN: u32 = 8;

/// Default fetches allowed in one local day.
pub const DEFAULT_WEB_FETCHES_PER_DAY: u32 = 200;

/// Default fetches allowed to one host in a rolling minute.
pub const DEFAULT_WEB_PER_HOST_PER_MINUTE: u32 = 10;

/// Default lifetime of an `ask_once_per_site` approval, in days.
pub const DEFAULT_WEB_ALLOW_EXPIRY_DAYS: u64 = 30;

/// Default cap on a whole URL, in bytes. Over the cap is refused, never
/// truncated: the URL is an outbound channel, so its length is itself data.
pub const DEFAULT_WEB_MAX_URL_BYTES: usize = 512;

/// Default cap on the query string of a URL, in bytes.
pub const DEFAULT_WEB_MAX_QUERY_BYTES: usize = 256;

/// Who is asked before a web read (`[web] mode`).
///
/// The mode changes **who is asked**, never the deterministic egress gate or
/// the private-data rule. W1 ships the config and the deterministic gate; the
/// `smart`/`ask_once_per_site` memory is a later slice, so both currently ask
/// on an unseen host (fail closed) rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebMode {
    /// Nobody for a seen host; an unseen host is judged later (W2). W1: an
    /// unseen host runs silently unless the turn carries private data or
    /// untrusted content.
    #[default]
    OpenRead,
    /// Unseen host when the judge is ambiguous or unavailable. W1 has no
    /// judge, so an unseen host asks.
    Smart,
    /// First read of a registry-controlled domain, then remembered. W1 has no
    /// registry yet, so an unseen host asks.
    AskOncePerSite,
    /// Every read asks.
    AlwaysAsk,
}

impl WebMode {
    /// Lowercase config label used in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            WebMode::OpenRead => "open_read",
            WebMode::Smart => "smart",
            WebMode::AskOncePerSite => "ask_once_per_site",
            WebMode::AlwaysAsk => "always_ask",
        }
    }
}

impl std::fmt::Display for WebMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Web egress settings (`[web]` in `config.toml`).
///
/// The defaults are the documented ones: `open_read`, no domain lists,
/// `http` and `https`, ports 80/443, a 256 KiB / 15 s whole-fetch budget, and
/// conservative fetch counters. An unknown `mode` is a config error (serde
/// rejects the value), never a silent fall back to `open_read`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    /// Who is asked before a read.
    pub mode: WebMode,
    /// Domains that may be read without the seen-before ask rule. A leading
    /// `*.` (or `.`) is optional; a bare domain matches it and its subdomains.
    pub allow_domains: Vec<String>,
    /// Domains that may never be read. **Deny wins in every mode**, over any
    /// allow entry or remembered approval.
    pub deny_domains: Vec<String>,
    /// Refuse plain `http` URLs.
    pub https_only: bool,
    /// Ports a fetch may reach. Every other port is refused.
    pub port_allowlist: Vec<u16>,
    /// Redirect hops followed per fetch (the first request is not counted).
    pub max_redirects: usize,
    /// Whole-fetch byte cap, body included.
    pub max_bytes: usize,
    /// Whole-fetch wall-clock cap in seconds, redirects included.
    pub timeout_secs: u64,
    /// Content types the extractor is willing to render.
    pub content_types: Vec<String>,
    /// Fetches allowed in one turn.
    pub fetches_per_turn: u32,
    /// Fetches allowed in one local day.
    pub fetches_per_day: u32,
    /// Fetches allowed to one host in a rolling minute.
    pub per_host_per_minute: u32,
    /// Lifetime of an `ask_once_per_site` approval, in days.
    pub allow_expiry_days: u64,
    /// Cap on a whole URL, in bytes (over the cap is refused, never truncated).
    pub max_url_bytes: usize,
    /// Cap on a URL's query string, in bytes.
    pub max_query_bytes: usize,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            mode: DEFAULT_WEB_MODE,
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            https_only: false,
            port_allowlist: DEFAULT_WEB_PORTS.to_vec(),
            max_redirects: DEFAULT_WEB_MAX_REDIRECTS,
            max_bytes: DEFAULT_WEB_MAX_BYTES,
            timeout_secs: DEFAULT_WEB_TIMEOUT_SECS,
            content_types: DEFAULT_WEB_CONTENT_TYPES
                .iter()
                .map(|kind| (*kind).to_string())
                .collect(),
            fetches_per_turn: DEFAULT_WEB_FETCHES_PER_TURN,
            fetches_per_day: DEFAULT_WEB_FETCHES_PER_DAY,
            per_host_per_minute: DEFAULT_WEB_PER_HOST_PER_MINUTE,
            allow_expiry_days: DEFAULT_WEB_ALLOW_EXPIRY_DAYS,
            max_url_bytes: DEFAULT_WEB_MAX_URL_BYTES,
            max_query_bytes: DEFAULT_WEB_MAX_QUERY_BYTES,
        }
    }
}

impl WebConfig {
    /// The whole-fetch wall-clock cap; a zero falls back to the default
    /// instead of disabling the cap.
    pub fn timeout(&self) -> std::time::Duration {
        let secs = if self.timeout_secs == 0 {
            DEFAULT_WEB_TIMEOUT_SECS
        } else {
            self.timeout_secs
        };
        std::time::Duration::from_secs(secs)
    }

    /// True when `port` is in the allowlist.
    pub fn port_allowed(&self, port: u16) -> bool {
        self.port_allowlist.contains(&port)
    }

    /// True when the response's `Content-Type` essence is in the allowlist.
    ///
    /// A missing or empty header is **refused** like any other type outside
    /// the list: the body sniffer must never widen the owner's allowlist on
    /// its own. An empty header is rendered only when the owner explicitly
    /// lists an empty entry (e.g. `content_types = ["text/html", ""]`),
    /// which is the owner opting in to the sniffer for headerless servers.
    pub fn content_type_allowed(&self, content_type: &str) -> bool {
        let essence = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        self.content_types.iter().any(|allowed| {
            let allowed = allowed.trim().to_ascii_lowercase();
            if allowed.is_empty() {
                essence.is_empty()
            } else {
                allowed == essence
            }
        })
    }
}
