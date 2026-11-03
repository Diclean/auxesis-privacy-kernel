//! The connector's own annotation hints and the risk they map to.

use kernel_broker::Risk;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One MCP annotation hint, in a stable order.
///
/// The wire keys are camelCase (MCP's `readOnlyHint`/`destructiveHint`/…; the
/// connector hub also sends `createHint`/`updateHint`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum McpTag {
    /// The tool only reads.
    ReadOnlyHint,
    /// The tool creates a record.
    CreateHint,
    /// The tool updates a record.
    UpdateHint,
    /// The tool can destroy data.
    DestructiveHint,
    /// Repeating the call is safe.
    IdempotentHint,
    /// The tool reaches outside the connector's own data.
    OpenWorldHint,
}

impl McpTag {
    /// Every tag, in the fixed order used for parsing and for [`risk_from_tags`].
    pub const ALL: [McpTag; 6] = [
        McpTag::ReadOnlyHint,
        McpTag::CreateHint,
        McpTag::UpdateHint,
        McpTag::DestructiveHint,
        McpTag::IdempotentHint,
        McpTag::OpenWorldHint,
    ];

    /// The wire key for this hint.
    pub fn key(self) -> &'static str {
        match self {
            McpTag::ReadOnlyHint => "readOnlyHint",
            McpTag::CreateHint => "createHint",
            McpTag::UpdateHint => "updateHint",
            McpTag::DestructiveHint => "destructiveHint",
            McpTag::IdempotentHint => "idempotentHint",
            McpTag::OpenWorldHint => "openWorldHint",
        }
    }

    /// Parse the raw `annotations` object into a stable tag list.
    ///
    /// Only the exact camelCase keys with a literal `true` become tags; a
    /// missing object, a wrong type or an unknown key contributes nothing.
    pub fn from_annotations(annotations: Option<&Value>) -> Vec<McpTag> {
        let Some(map) = annotations.and_then(Value::as_object) else {
            return Vec::new();
        };
        McpTag::ALL
            .iter()
            .copied()
            .filter(|tag| map.get(tag.key()).and_then(Value::as_bool) == Some(true))
            .collect()
    }
}

/// Map the connector's own annotation hints to a [`Risk`].
///
/// `destructiveHint` is [`Risk::High`]; `createHint`/`updateHint` are
/// [`Risk::Medium`]; `readOnlyHint` without any mutation hint is [`Risk::Low`];
/// **anything else, including no tags at all, is [`Risk::High`]** — unknown
/// means dangerous.
pub fn risk_from_tags(tags: &[McpTag]) -> Risk {
    if tags.is_empty() {
        return Risk::High;
    }
    if tags.contains(&McpTag::DestructiveHint) {
        return Risk::High;
    }
    if tags.contains(&McpTag::CreateHint) || tags.contains(&McpTag::UpdateHint) {
        return Risk::Medium;
    }
    if tags.contains(&McpTag::ReadOnlyHint) {
        return Risk::Low;
    }
    Risk::High
}

/// Where a descriptor's [`Risk`] came from.
///
/// The server's `annotations` are untrusted, so a `Low` risk derived from a
/// server hint ([`RiskBasis::ServerHint`]) is **not** trustworthy on its own.
/// It may only drive an `allow` rule once a local classifier independently
/// agrees ([`RiskBasis::Corroborated`]); until then the broker must treat it as
/// `ask`. [`RiskBasis::Default`] is the conservative unknown-means-dangerous
/// value used when the server supplied no usable hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBasis {
    /// Derived only from the server's own annotation hints (untrusted).
    ServerHint,
    /// A local classifier independently agrees with the hint.
    Corroborated,
    /// No usable hint: the conservative default (`Risk::High`).
    Default,
}

impl RiskBasis {
    /// Whether a `Low` risk on this basis may be trusted enough for an `allow`
    /// rule. Only an independently corroborated classification qualifies.
    pub fn is_corroborated(self) -> bool {
        matches!(self, RiskBasis::Corroborated)
    }
}
