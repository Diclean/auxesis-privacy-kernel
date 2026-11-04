//! Deterministic web egress policy.
//!
//! A web `GET` is **egress**, not a harmless local read: the URL path/query
//! and the DNS lookup both leave the machine before anything is refused. This
//! module holds the one deterministic policy every fetch funnels through:
//!
//! - [`WebGate::check`] refuses a URL *shape* before any socket, and
//!   [`WebGate::decide`] adds the mode/private-data rule on top. The gate is
//!   the control; a judge (W2) is only ever advisory. On a sensitive turn
//!   (taint or private owner data) **every** fetch asks
//!   ([`AskReason::SensitiveTurn`]): any silent request is itself a covert
//!   channel, because the origin — or anyone who can observe it — sees
//!   *whether* the agent asked, and the model can condition that request on a
//!   private bit. There is no bare-root exception left, no seen-origin
//!   exception, and an allowlist never exempts a host on a sensitive turn. A
//!   non-sensitive turn keeps the mode and allowlist rules, where the
//!   already-seen set still decides `ask_once_per_site` and `smart`.
//! - [`WebBudget`] is checked before an approval card and reserved at **connect
//!   time** (every hop, the first included), so a refused or unapproved fetch
//!   never consumes a slot. [`FetchEgress`] shares one budget, the turn's
//!   ask-rule facts and the approved origins with the fetcher, so every
//!   redirect hop re-enters the rule and the counters too.
//! - [`WebFetchEvent`] is the single `web.fetch` audit row per attempt. It
//!   records the **host**, a SHA-256 of the query and — for a refused
//!   redirect hop — a SHA-256 of the URL, never the query or URL text: those
//!   are themselves the outbound data the policy exists to protect.
//!
//! Deny always wins: `deny_domains` beats `allow_domains`, a remembered
//! approval, and every mode. An unknown or missing state fails closed.
//!
//! Friction, stated plainly (a maintainer decision): after any web
//! read or private read in a conversation, every further fetch asks. That is
//! deliberate — a silent egress while the turn is sensitive is a channel.

mod audit;
mod budget;
mod decision;
mod fetch;
mod gate;
mod host;

pub use audit::WebFetchEvent;
pub use budget::{BudgetKind, WebBudget};
pub use decision::{AskReason, CheckedUrl, DenyReason, EgressContext, EgressDecision};
pub use fetch::{FetchEgress, OriginReceipt, RefusedRedirectHop};
pub use gate::WebGate;
pub use host::domain_matches;

#[cfg(test)]
mod tests;
