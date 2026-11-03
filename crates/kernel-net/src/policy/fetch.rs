//! The per-fetch egress authority shared with the fetcher: approved origins,
//! receipts and the redirect hops refused for approval.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use super::audit::sha256_hex;
use super::budget::WebBudget;
use super::decision::EgressContext;
use super::host::{bare_host, origin_of, url_origin_key};

/// One redirect hop the fetcher refused because it needed its own approval.
///
/// The engine reads these back from [`FetchEgress`] after the tool ran and
/// writes one `web.fetch` row per refusal. It carries the hop host and a
/// SHA-256 of the refused URL — never the URL or query text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedRedirectHop {
    /// Host of the refused hop.
    pub host: String,
    /// SHA-256 (lowercase hex) of the refused hop URL.
    pub url_sha256: String,
}

/// The per-fetch egress authority the engine shares with the fetcher.
///
/// A redirect leaves the decided URL behind, and every hop is re-checked —
/// but not every hop re-runs the full decision:
///
/// - **Every hop** re-enters the deterministic shape gate
///   ([`WebGate::check_before_resolve`](super::gate::WebGate::check_before_resolve) +
///   [`WebGate::check_after_resolve`](super::gate::WebGate::check_after_resolve):
///   URL shape, deny domains, allowed port, HTTPS-downgrade refusal) before any
///   DNS lookup. Its origin must be one of [`FetchEgress::approved_origins`],
///   and its destination host is reserved from the shared per-turn/day/host
///   counters right before its connect.
/// - **A hop that leaves the origin's host** is never followed silently: its
///   destination origin re-runs
///   [`WebGate::decide_checked`](super::gate::WebGate::decide_checked) under
///   these facts, and when that does not allow it the hop is refused with its
///   own card ([`crate::FetchError::RedirectNeedsApproval`]), so the card issued
///   for the original URL can never authorize another origin.
/// - **A same-host hop that changes port** re-runs
///   [`WebGate::decide_checked`](super::gate::WebGate::decide_checked)
///   when the turn is sensitive (taint or private data), and can be refused.
/// - **A same-host, same-port hop** does **not** re-enter
///   [`WebGate::decide_checked`](super::gate::WebGate::decide_checked): the card
///   for that origin already covered it.
///   Only the shape gate and the budget reservation above apply.
///
/// Tools that run without the engine (tests, search-side fetchers) pass no
/// [`FetchEgress`]: hops then decide with [`EgressContext::default`], clean and
/// unseen, so every mode stricter than `open_read` refuses a cross-origin hop —
/// fail closed.
#[derive(Debug, Clone)]
pub struct FetchEgress {
    /// The turn's sensitive-turn facts: taint and private owner data. The
    /// `seen_origin` fact of [`EgressContext`] is recomputed per hop by
    /// `FetchEgress::redirect_context`.
    pub context: EgressContext,
    /// Origins (`scheme://host:port`) already fetched in this conversation. A
    /// hop lands on one of them (or stays on the origin the card covered)
    /// without a new card; any other origin is unseen.
    pub seen_origins: Arc<BTreeSet<String>>,
    /// The origins (`scheme://host:port`) this call was approved for: the
    /// declared hosts plus the origin of the URL argument. The fetcher refuses
    /// a connection to any other origin, the first hop included, before DNS.
    pub approved_origins: Arc<BTreeSet<String>>,
    /// The shared fetch counters, reserved right before every hop connects.
    pub budget: Arc<Mutex<WebBudget>>,
    /// Redirect hops refused for approval during this fetch, for the engine's
    /// `web.fetch` audit row. Empty when the caller does not audit.
    pub refused_hops: Arc<Mutex<Vec<RefusedRedirectHop>>>,
    /// Set once any request in this fetch received an HTTP response. The
    /// engine reads it back to decide whether the origin may be recorded as
    /// seen: a DNS/TLS/connect/timeout failure leaves it false, so an origin
    /// is never marked seen by a fetch that reached no server.
    pub received_response: Arc<Mutex<bool>>,
    /// The origins that actually answered during this call, with the HTTP
    /// status and body bytes of each. An origin appears only after a server
    /// responded, so the engine can attribute bytes and status per target.
    pub received_origins: Arc<Mutex<BTreeMap<String, OriginReceipt>>>,
}

/// What one origin sent back during a call: the status of its last response
/// and the response body bytes read from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OriginReceipt {
    /// HTTP status of the last response from this origin.
    pub http_status: u16,
    /// Response body bytes read from this origin, after the body caps.
    pub bytes: usize,
}

impl FetchEgress {
    /// Whether the call was approved for the origin of `url`.
    pub fn approves(&self, url: &reqwest::Url) -> bool {
        self.approved_origins.contains(&url_origin_key(url))
    }

    /// Record one response from `url` (any status): the origin is now a
    /// server that answered, and `http_status` is its status.
    pub fn note_origin_response(&self, url: &str, http_status: u16) {
        self.note_received_response();
        if let Some(origin) = origin_of(url) {
            self.with_origins(|origins| {
                origins.entry(origin).or_default().http_status = http_status
            });
        }
    }

    /// Add `bytes` of response body read from `url`'s origin.
    pub fn note_origin_bytes(&self, url: &str, bytes: usize) {
        if let Some(origin) = origin_of(url) {
            self.with_origins(|origins| origins.entry(origin).or_default().bytes += bytes);
        }
    }

    /// What `origin` answered during this call, or `None` when it never did.
    pub fn origin_receipt(&self, origin: &str) -> Option<OriginReceipt> {
        match self.received_origins.lock() {
            Ok(origins) => origins.get(origin).copied(),
            Err(poisoned) => poisoned.into_inner().get(origin).copied(),
        }
    }

    fn with_origins<R>(&self, f: impl FnOnce(&mut BTreeMap<String, OriginReceipt>) -> R) -> R {
        match self.received_origins.lock() {
            Ok(mut origins) => f(&mut origins),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }

    /// Record that a request received an HTTP response (any status). Only then
    /// may the origin be remembered as seen.
    pub fn note_received_response(&self) {
        match self.received_response.lock() {
            Ok(mut reached) => *reached = true,
            Err(poisoned) => *poisoned.into_inner() = true,
        }
    }

    /// True once a request in this fetch received an HTTP response. False for
    /// a fetch that failed before any server answered (DNS, connect, TLS,
    /// timeout).
    pub fn received_response(&self) -> bool {
        match self.received_response.lock() {
            Ok(reached) => *reached,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// Record one redirect hop refused for approval, for the engine's audit
    /// row. Stores the host and a SHA-256 of the URL, never the URL text. A
    /// URL that does not parse still gets a row, with an empty host.
    pub fn note_refused_hop(&self, url: &str) {
        let entry = RefusedRedirectHop {
            host: reqwest::Url::parse(url)
                .ok()
                .and_then(|parsed| bare_host(&parsed))
                .unwrap_or_default(),
            url_sha256: sha256_hex(url.as_bytes()),
        };
        match self.refused_hops.lock() {
            Ok(mut hops) => hops.push(entry),
            Err(poisoned) => poisoned.into_inner().push(entry),
        }
    }

    /// Take the redirect hops refused for approval so far.
    pub fn take_refused_hops(&self) -> Vec<RefusedRedirectHop> {
        match self.refused_hops.lock() {
            Ok(mut hops) => std::mem::take(&mut *hops),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        }
    }
}
