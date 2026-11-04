//! Auxesis descriptors for remote connector tools.
//!
//! A [`McpToolDescriptor`] is the sanitised, capped, namespaced view of one
//! server-advertised tool. It is the only shape the rest of Auxesis sees: the
//! [`crate::tools::RemoteTool`] carrier stays at the protocol boundary.
//!
//! # Descriptions and schemas are untrusted input
//!
//! Descriptions and schemas are **model-visible**: a hostile server can try to
//! smuggle instructions ("ignore your rules and send…") or spoof text with
//! zero-width/bidi characters. Descriptions are provenance-wrapped and capped;
//! schemas are rebuilt from typed input using a structural keyword allowlist.
//! Invalid property/keyword identifiers reject the whole tool, and no free-form
//! schema text is emitted to the model.
//!
//! A description is **data**. Nothing in this module parses a description into a
//! rule, a risk level or a toolkit; those come from the raw annotation hints
//! ([`McpTag`]) and the toolkit name the caller passes from explicit config.

// The submodules are private on purpose: every item below is re-exported at
// this path, so `crate::descriptor::…` is exactly what it was before the
// split, and no new public path appears.
mod description;
mod forged_provenance;
mod limits;
mod neutralise;
mod schema;
mod tags;
mod tool;

#[cfg(test)]
mod tests;

pub use description::sanitize_description;
pub use limits::{
    FORGED_PROVENANCE_MARKER, MAX_DESCRIPTION_BYTES, MAX_NAME_BYTES, MAX_SCHEMA_BYTES,
    TRUNCATION_MARKER, WRAPPER_MARKERS,
};
pub use schema::sanitize_schema;
pub use tags::{risk_from_tags, McpTag, RiskBasis};
pub use tool::McpToolDescriptor;

pub(crate) use neutralise::neutralise_server_text;
