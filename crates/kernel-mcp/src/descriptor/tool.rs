//! The sanitised, namespaced descriptor of one remote tool.

use std::fmt;

use kernel_broker::Risk;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::description::sanitize_description;
use super::limits::MAX_NAME_BYTES;
use super::schema::sanitize_schema;
use super::tags::{risk_from_tags, McpTag, RiskBasis};
use crate::naming::{display_name, logical_name};
use crate::tools::{RemoteTool, UntrustedText};

/// A sanitised, namespaced descriptor for one server-advertised tool.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolDescriptor {
    /// The connector/server the tool came from.
    pub server: String,
    /// The exact remote slug, as advertised (never truncated — it is the call
    /// argument).
    pub remote_name: String,
    /// The provider-legal wire name the model sees and the engine passes back.
    pub wire_name: String,
    /// The toolkit that owns the slug, from explicit config only.
    pub toolkit: String,
    /// The connector's own annotation hints.
    pub tags: Vec<McpTag>,
    /// Where [`risk`](Self::risk) came from; a [`RiskBasis::ServerHint`] `Low`
    /// must never drive an `allow` rule without corroboration.
    pub risk_basis: RiskBasis,
    /// Sanitised description, at most [`MAX_DESCRIPTION_BYTES`](super::limits::MAX_DESCRIPTION_BYTES) bytes.
    pub description: UntrustedText,
    /// Sanitised, capped input schema.
    pub schema: Value,
}

impl fmt::Debug for McpToolDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let schema = serde_json::to_string(&self.schema).unwrap_or_default();
        f.debug_struct("McpToolDescriptor")
            .field("server_bytes", &self.server.len())
            .field("server_hash", &crate::naming::short_hash(&self.server))
            .field("remote_name_bytes", &self.remote_name.len())
            .field(
                "remote_name_hash",
                &crate::naming::short_hash(&self.remote_name),
            )
            .field("wire_name_bytes", &self.wire_name.len())
            .field(
                "wire_name_hash",
                &crate::naming::short_hash(&self.wire_name),
            )
            .field("toolkit", &self.toolkit)
            .field("tags", &self.tags)
            .field("risk_basis", &self.risk_basis)
            .field("description", &self.description)
            .field("schema_bytes", &schema.len())
            .field("schema_hash", &crate::naming::short_hash(&schema))
            .finish()
    }
}

impl McpToolDescriptor {
    /// Build a descriptor, or `None` when its name or schema is unusable.
    ///
    /// A name outside `[A-Za-z0-9_-]{1,48}` is **refused**, never rewritten:
    /// the name is the argument to `tools/call`, so a changed name could target
    /// a different tool. This is the defence-in-depth check after wire parsing.
    pub fn from_remote(
        server: &str,
        toolkit: &str,
        wire_name: String,
        remote: &RemoteTool,
    ) -> Option<Self> {
        if !Self::name_is_valid(&remote.name)
            || !crate::naming::valid_wire_component(server)
            || wire_name != crate::naming::wire_name(server, &remote.name)
            || wire_name.len() > crate::naming::MAX_WIRE_NAME_BYTES
        {
            return None;
        }
        let schema = sanitize_schema(&remote.input_schema)?;
        let tags = McpTag::from_annotations(remote.annotations.as_ref());
        let risk_basis = if tags.is_empty() {
            RiskBasis::Default
        } else {
            RiskBasis::ServerHint
        };
        Some(Self {
            server: server.to_owned(),
            remote_name: remote.name.clone(),
            wire_name,
            toolkit: toolkit.to_owned(),
            tags,
            risk_basis,
            description: UntrustedText::new(sanitize_description(
                remote.description.as_ref().map_or("", UntrustedText::raw),
            )),
            schema,
        })
    }

    /// Whether a remote tool name is within the accepted bounds.
    pub fn name_is_valid(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= MAX_NAME_BYTES
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    }

    /// The risk for this tool, derived only from its annotation hints.
    pub fn risk(&self) -> Risk {
        risk_from_tags(&self.tags)
    }

    /// Whether this descriptor's risk rests only on the server's own hint.
    ///
    /// A caller seeding an `allow` rule must require corroboration
    /// ([`RiskBasis::is_corroborated`]) before trusting a server-hint `Low`.
    pub fn risk_is_server_hint(&self) -> bool {
        self.risk_basis == RiskBasis::ServerHint
    }

    /// The logical name (`<server>.<toolkit>.<tool>`).
    pub fn logical_name(&self) -> String {
        logical_name(&self.server, &self.toolkit, &self.remote_name)
    }

    /// The dotted human/display name (`mcp.<server>.<tool>`).
    pub fn display_name(&self) -> String {
        display_name(&self.server, &self.remote_name)
    }
}
