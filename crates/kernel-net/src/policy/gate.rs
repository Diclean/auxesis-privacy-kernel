//! The deterministic URL gate: shape checks and the mode/private-data rule.

use kernel_core::WebConfig;
use std::net::IpAddr;

use super::audit::sha256_hex;
use super::decision::{AskReason, CheckedUrl, DenyReason, EgressContext, EgressDecision};
use super::host::{bare_host, domain_matches, is_obfuscated_numeric_host};

/// The deterministic egress gate, built from `[web]`.
#[derive(Debug, Clone)]
pub struct WebGate {
    config: WebConfig,
    /// Tests only: allow loopback IP literals and arbitrary ports so a
    /// `wiremock` server is reachable. Production is always `false`.
    #[cfg(any(test, feature = "testing"))]
    permissive: bool,
}

impl WebGate {
    /// Build a gate from the `[web]` section.
    pub fn new(config: WebConfig) -> Self {
        Self {
            config,
            #[cfg(any(test, feature = "testing"))]
            permissive: false,
        }
    }

    /// Tests only: the shape checks for ports/IP literals are relaxed so a
    /// loopback `wiremock` server can be reached. `deny_domains` and the URL
    /// caps still apply.
    #[cfg(any(test, feature = "testing"))]
    pub fn permissive_for_tests(config: WebConfig) -> Self {
        Self {
            config,
            permissive: true,
        }
    }

    /// The `[web]` settings this gate enforces.
    pub fn config(&self) -> &WebConfig {
        &self.config
    }

    /// The configured mode label.
    pub fn mode_label(&self) -> &'static str {
        self.config.mode.as_str()
    }

    fn bypasses_shape(&self) -> bool {
        #[cfg(any(test, feature = "testing"))]
        {
            self.permissive
        }
        #[cfg(not(any(test, feature = "testing")))]
        {
            false
        }
    }

    /// Checks that need no DNS lookup: scheme, `https_only`, the URL/query
    /// caps and `deny_domains`. Safe to run **before** a lookup, so a
    /// deny-listed or over-long URL resolves nothing.
    pub fn check_before_resolve(&self, url: &reqwest::Url) -> Result<(), DenyReason> {
        match url.scheme() {
            "http" | "https" => {}
            _ => return Err(DenyReason::NotHttp),
        }
        if self.config.https_only && url.scheme() == "http" {
            return Err(DenyReason::HttpsOnly);
        }
        if url.as_str().len() > self.config.max_url_bytes {
            return Err(DenyReason::UrlTooLong);
        }
        if let Some(query) = url.query() {
            if query.len() > self.config.max_query_bytes {
                return Err(DenyReason::QueryTooLong);
            }
        }
        let host = bare_host(url).ok_or(DenyReason::NotHttp)?;
        if self
            .config
            .deny_domains
            .iter()
            .any(|pattern| domain_matches(pattern, &host))
        {
            return Err(DenyReason::DeniedDomain);
        }
        Ok(())
    }

    /// Checks that need only the URL, not DNS or a connection: port allowlist
    /// and URL-shape refusals (IP literals, obfuscated numeric spellings,
    /// punycode/IDN labels). Despite the historical name, this is safe to run
    /// before resolution.
    pub fn check_after_resolve(&self, url: &reqwest::Url) -> Result<(), DenyReason> {
        let port = url.port_or_known_default().ok_or(DenyReason::NotHttp)?;
        if !self.bypasses_shape() && !self.config.port_allowed(port) {
            return Err(DenyReason::PortNotAllowed);
        }
        let host = bare_host(url).ok_or(DenyReason::NotHttp)?;
        self.check_host_shape(&host)
    }

    /// The host-shape refusals alone (also usable by a caller that already
    /// resolved the URL).
    pub fn check_host_shape(&self, host: &str) -> Result<(), DenyReason> {
        if self.bypasses_shape() {
            return Ok(());
        }
        if host.is_empty() {
            return Err(DenyReason::NotHttp);
        }
        let lowered = host.to_ascii_lowercase();
        if lowered.parse::<IpAddr>().is_ok() {
            // A bare public IP literal is still an egress address the owner
            // never typed. Private/reserved literals are handled by the SSRF
            // guard; the gate refuses the shape itself.
            return Err(DenyReason::IpLiteral);
        }
        if is_obfuscated_numeric_host(&lowered) {
            return Err(DenyReason::ObfuscatedHost);
        }
        if lowered.split('.').any(|label| label.starts_with("xn--")) {
            return Err(DenyReason::PunycodeHost);
        }
        Ok(())
    }

    /// The full deterministic check: parse, pre-resolve, post-resolve.
    pub fn check(&self, input: &str) -> Result<CheckedUrl, DenyReason> {
        if input.len() > self.config.max_url_bytes {
            return Err(DenyReason::UrlTooLong);
        }
        let url = reqwest::Url::parse(input).map_err(|_| DenyReason::NotHttp)?;
        self.check_before_resolve(&url)?;
        self.check_after_resolve(&url)?;
        let host = bare_host(&url).ok_or(DenyReason::NotHttp)?;
        Ok(CheckedUrl { url, host })
    }

    /// Best-effort host of `input`, for an audit row on a refused URL. `None`
    /// when the input does not parse.
    pub fn host_of(&self, input: &str) -> Option<String> {
        reqwest::Url::parse(input)
            .ok()
            .and_then(|url| bare_host(&url))
    }

    /// The mode/private-data rule, on top of [`WebGate::check`].
    ///
    /// The order is the contract: a denied URL is never asked about, and a
    /// judge (W2) is only ever consulted for an origin that passed and was not
    /// already seen.
    pub fn decide(&self, input: &str, ctx: &EgressContext) -> EgressDecision {
        match self.check(input) {
            Ok(checked) => self.decide_checked(&checked, ctx),
            Err(reason) => EgressDecision::Deny(reason),
        }
    }

    /// [`WebGate::decide`] for a URL that already passed [`WebGate::check`],
    /// so a caller that needs the host does not parse and shape-check twice.
    ///
    /// The order is the contract: on a sensitive turn **every** fetch asks,
    /// and that rule is never bypassed by `allow_domains` (an allowlist
    /// exempts a host from the *mode*, never from the sensitive-turn card).
    /// The already-seen origin is read only by the non-sensitive mode rules.
    pub fn decide_checked(&self, checked: &CheckedUrl, ctx: &EgressContext) -> EgressDecision {
        // Any silent request is a channel: on a sensitive turn every fetch
        // asks, before the allowlist and before the mode rules.
        if ctx.tainted || ctx.carries_private_data {
            return EgressDecision::Ask(AskReason::SensitiveTurn);
        }
        if self
            .config
            .allow_domains
            .iter()
            .any(|pattern| domain_matches(pattern, checked.host.as_str()))
        {
            return EgressDecision::Allow;
        }
        match self.config.mode {
            kernel_core::WebMode::OpenRead => EgressDecision::Allow,
            kernel_core::WebMode::AlwaysAsk => EgressDecision::Ask(AskReason::ModeAlwaysAsk),
            kernel_core::WebMode::AskOncePerSite => {
                if ctx.seen_origin {
                    EgressDecision::Allow
                } else {
                    EgressDecision::Ask(AskReason::ModeAskOncePerSite)
                }
            }
            kernel_core::WebMode::Smart => {
                if ctx.seen_origin {
                    EgressDecision::Allow
                } else {
                    EgressDecision::Ask(AskReason::SmartJudgeUnavailable)
                }
            }
        }
    }

    /// True when the fetch's response `Content-Type` may be rendered.
    pub fn content_type_allowed(&self, content_type: &str) -> bool {
        self.config.content_type_allowed(content_type)
    }

    /// SHA-256 (lowercase hex) of the query string, or `None` when the URL
    /// has no query. The query text itself is never logged.
    pub fn query_sha256(&self, url: &reqwest::Url) -> Option<String> {
        url.query().map(|query| sha256_hex(query.as_bytes()))
    }

    /// SHA-256 (lowercase hex) of text a declared-host tool sends off the
    /// machine (for example a place name). Only the hash is ever audited.
    pub fn text_sha256(&self, text: &str) -> String {
        sha256_hex(text.as_bytes())
    }
}

impl Default for WebGate {
    fn default() -> Self {
        Self::new(WebConfig::default())
    }
}
