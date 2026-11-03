//! The egress decision vocabulary: turn facts, ask/deny reasons and the outcome.

use super::host::url_origin_key;

/// The per-turn conversation facts the ask rule depends on.
///
/// The engine fills this in; it never comes from the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EgressContext {
    /// The conversation holds untrusted content (WS-C taint).
    pub tainted: bool,
    /// The turn read mail/calendar/memory/notes: private owner data.
    pub carries_private_data: bool,
    /// This exact origin — `(scheme, host, effective port)` — was fetched
    /// before in this conversation and a response was actually received. Only
    /// the non-sensitive mode rules read it (`ask_once_per_site`, `smart`); a
    /// sensitive turn never does. An allowlist never counts as seen on its
    /// own.
    pub seen_origin: bool,
}

/// Why a fetch must ask before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskReason {
    /// A sensitive turn (taint or private owner data). Every fetch asks:
    /// there is no exception, not the bare root of an already-seen origin,
    /// not an allowlisted host, and not a re-fetch of a URL that already ran.
    SensitiveTurn,
    /// `[web] mode = "always_ask"`.
    ModeAlwaysAsk,
    /// `ask_once_per_site` with no remembered approval (W6 lands later).
    ModeAskOncePerSite,
    /// `smart` with no judge available (W5 lands later); fail closed.
    SmartJudgeUnavailable,
}

impl AskReason {
    /// Stable lowercase label for the audit record.
    pub fn as_str(self) -> &'static str {
        match self {
            AskReason::SensitiveTurn => "sensitive_turn",
            AskReason::ModeAlwaysAsk => "mode_always_ask",
            AskReason::ModeAskOncePerSite => "mode_ask_once_per_site",
            AskReason::SmartJudgeUnavailable => "smart_judge_unavailable",
        }
    }
}

/// Why the deterministic gate refused a URL. It is a refusal, never a silent
/// fallback, and it opens no socket and performs no DNS lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// Not an absolute `http`/`https` URL.
    NotHttp,
    /// `https_only = true` and the URL is plain `http`.
    HttpsOnly,
    /// A redirect downgraded an HTTPS fetch to plain HTTP.
    HttpsDowngrade,
    /// The port is not in `port_allowlist`.
    PortNotAllowed,
    /// The whole URL is over `max_url_bytes` (refused, never truncated).
    UrlTooLong,
    /// The query string is over `max_query_bytes`.
    QueryTooLong,
    /// The host is a bare IP literal, not a name.
    IpLiteral,
    /// The host is an obfuscated numeric spelling (`2130706433`, `0x7f.1`).
    ObfuscatedHost,
    /// The host carries a punycode/IDN label (`xn--…`).
    PunycodeHost,
    /// The host matched `deny_domains`. Deny wins in every mode.
    DeniedDomain,
    /// The per-turn fetch budget is exhausted.
    BudgetTurn,
    /// The per-day fetch budget is exhausted.
    BudgetDay,
    /// The per-host-per-minute fetch budget is exhausted.
    BudgetHost,
    /// The connection targets an origin the call was not approved for: not a
    /// declared host and not the URL argument's origin. Refused before DNS.
    OriginNotApproved,
}

impl DenyReason {
    /// Stable lowercase label for the audit record.
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::NotHttp => "not_http",
            DenyReason::HttpsOnly => "https_only",
            DenyReason::HttpsDowngrade => "https_downgrade",
            DenyReason::PortNotAllowed => "port_not_allowed",
            DenyReason::UrlTooLong => "url_too_long",
            DenyReason::QueryTooLong => "query_too_long",
            DenyReason::IpLiteral => "ip_literal",
            DenyReason::ObfuscatedHost => "obfuscated_host",
            DenyReason::PunycodeHost => "punycode_host",
            DenyReason::DeniedDomain => "denied_domain",
            DenyReason::BudgetTurn => "budget_turn",
            DenyReason::BudgetDay => "budget_day",
            DenyReason::BudgetHost => "budget_host",
            DenyReason::OriginNotApproved => "origin_not_approved",
        }
    }
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the policy says about one URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDecision {
    /// The gate passed and no rule requires a card.
    Allow,
    /// The gate passed but a card is required first.
    Ask(AskReason),
    /// The gate refused the URL outright.
    Deny(DenyReason),
}

impl EgressDecision {
    /// Stable label for the audit record.
    pub fn as_str(self) -> &'static str {
        match self {
            EgressDecision::Allow => "allow",
            EgressDecision::Ask(_) => "ask",
            EgressDecision::Deny(_) => "deny",
        }
    }
}

/// A URL that passed the deterministic shape checks.
#[derive(Debug, Clone)]
pub struct CheckedUrl {
    /// The parsed URL.
    pub url: reqwest::Url,
    /// The bare host (brackets stripped for IPv6 literals), lowercased.
    pub host: String,
}

impl CheckedUrl {
    /// The seen-origin key: `scheme://host:effective-port`. The non-sensitive
    /// mode rules key on origins, not hosts, so `http://h/p` and `https://h/p`
    /// are different origins, as are port 80 and port 443.
    pub fn origin_key(&self) -> String {
        url_origin_key(&self.url)
    }
}
