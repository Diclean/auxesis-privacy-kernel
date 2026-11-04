//! Mapping a remote tool slug to the toolkit that owns it.

use std::collections::BTreeMap;

/// An explicit `(server, slug) -> toolkit` map, fed by the `tools` config.
/// A toolkit is never guessed from a description or a name pattern.
#[derive(Debug, Clone, Default)]
pub struct ToolkitMap {
    exact: BTreeMap<(String, String), String>,
}

impl ToolkitMap {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one explicit slug.
    pub fn insert(&mut self, server: &str, remote_name: &str, toolkit: &str) {
        self.exact.insert(
            (server.to_owned(), remote_name.to_owned()),
            toolkit.to_owned(),
        );
    }

    /// Builder form: record every slug under one toolkit.
    pub fn with_toolkit(mut self, server: &str, toolkit: &str, remote_names: &[&str]) -> Self {
        for name in remote_names {
            self.insert(server, name, toolkit);
        }
        self
    }

    /// The toolkit owning `(server, remote_name)`, or `None` when unlisted.
    pub fn classify(&self, server: &str, remote_name: &str) -> Option<String> {
        self.exact
            .get(&(server.to_owned(), remote_name.to_owned()))
            .cloned()
    }
}
