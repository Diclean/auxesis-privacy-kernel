//! In-place rewriting of `mcp.toml`: only the tables that changed are touched.

use std::collections::BTreeSet;

use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value as EditValue};

use super::document::{inline_table_to_map, table_to_value, validate_server_entry};
use super::{McpDataClass, McpServerConfig, QuarantinedServer};

/// Edit the document's `server` entries to match `servers`, in place.
///
/// Only the entries that changed are touched. An entry is left exactly as it
/// was when its id is in `quarantined` (the owner must still see and fix it) or
/// when it matches an in-memory server; an id that is neither present nor
/// quarantined was deleted. New servers are appended.
pub(super) fn edit_server_entries(
    document: &mut DocumentMut,
    servers: &[McpServerConfig],
    quarantined: &[QuarantinedServer],
) {
    let keep: BTreeSet<&str> = quarantined.iter().map(|entry| entry.id.as_str()).collect();
    match document.as_table_mut().get_mut("server") {
        Some(Item::ArrayOfTables(array)) => edit_array_of_tables(array, servers, &keep),
        Some(Item::Value(EditValue::Array(array))) => {
            edit_inline_array(array, servers, &keep);
        }
        _ => {
            if !servers.is_empty() {
                let mut array = ArrayOfTables::new();
                for server in servers {
                    array.push(server_to_table(server));
                }
                document
                    .as_table_mut()
                    .insert("server", Item::ArrayOfTables(array));
            }
        }
    }
}

/// Whether one parsed document entry must be left untouched by a rewrite.
fn entry_kept(
    server: &McpServerConfig,
    servers: &[McpServerConfig],
    keep: &BTreeSet<&str>,
) -> bool {
    servers.iter().any(|candidate| candidate.id == server.id) || keep.contains(server.id.as_str())
}

/// Edit a `[[server]]` array of tables in place.
fn edit_array_of_tables(
    array: &mut ArrayOfTables,
    servers: &[McpServerConfig],
    keep: &BTreeSet<&str>,
) {
    let mut existing: Vec<(usize, McpServerConfig)> = Vec::new();
    for (index, table) in array.iter().enumerate() {
        let Ok(server) = validate_server_entry(&table_to_value(table)) else {
            continue;
        };
        existing.push((index, server));
    }
    for (index, current) in &existing {
        let Some(desired) = servers.iter().find(|server| server.id == current.id) else {
            continue;
        };
        if desired == current {
            continue;
        }
        let Some(table) = array.get_mut(*index) else {
            continue;
        };
        sync_server_fields(table, current, desired);
    }
    let mut removals: Vec<usize> = existing
        .iter()
        .filter(|(_, server)| !entry_kept(server, servers, keep))
        .map(|(index, _)| *index)
        .collect();
    removals.sort_unstable_by(|a, b| b.cmp(a));
    for index in removals {
        if index < array.len() {
            array.remove(index);
        }
    }
    for server in servers {
        if !existing.iter().any(|(_, current)| current.id == server.id) {
            array.push(server_to_table(server));
        }
    }
}

/// Edit an inline `server = [ ... ]` array in place.
fn edit_inline_array(array: &mut Array, servers: &[McpServerConfig], keep: &BTreeSet<&str>) {
    let mut existing: Vec<(usize, McpServerConfig)> = Vec::new();
    for (index, value) in array.iter().enumerate() {
        let Some(table) = value.as_inline_table() else {
            continue;
        };
        let Ok(server) = validate_server_entry(&toml::Value::Table(inline_table_to_map(table)))
        else {
            continue;
        };
        existing.push((index, server));
    }
    for (index, current) in &existing {
        let Some(desired) = servers.iter().find(|server| server.id == current.id) else {
            continue;
        };
        if desired == current {
            continue;
        }
        let Some(EditValue::InlineTable(inline)) = array.get_mut(*index) else {
            continue;
        };
        let mut table = inline.clone().into_table();
        sync_server_fields(&mut table, current, desired);
        *inline = table.into_inline_table();
    }
    let mut removals: Vec<usize> = existing
        .iter()
        .filter(|(_, server)| !entry_kept(server, servers, keep))
        .map(|(index, _)| *index)
        .collect();
    removals.sort_unstable_by(|a, b| b.cmp(a));
    for index in removals {
        if index < array.len() {
            array.remove(index);
        }
    }
    for server in servers {
        if !existing.iter().any(|(_, current)| current.id == server.id) {
            array.push(EditValue::InlineTable(
                server_to_table(server).into_inline_table(),
            ));
        }
    }
}

/// Update only the fields of `table` that differ between `current` and
/// `desired`, so comments and key order elsewhere in the entry survive.
fn sync_server_fields(table: &mut Table, current: &McpServerConfig, desired: &McpServerConfig) {
    if current.catalog_id != desired.catalog_id {
        set_optional_string(table, "catalog_id", desired.catalog_id.as_deref());
    }
    if current.data_class != desired.data_class {
        table.insert(
            "data_class",
            toml_edit::value(match desired.data_class {
                McpDataClass::Public => "public".to_owned(),
                McpDataClass::Sensitive => "sensitive".to_owned(),
            }),
        );
    }
    if current.stdio_confirmed != desired.stdio_confirmed {
        table.insert("stdio_confirmed", toml_edit::value(desired.stdio_confirmed));
    }
    if current.stdio_confirmation != desired.stdio_confirmation {
        set_optional_string(
            table,
            "stdio_confirmation",
            desired.stdio_confirmation.as_deref(),
        );
    }
    if current.approval != desired.approval {
        set_optional_string(table, "approval", desired.approval.as_deref());
    }
    if current.network != desired.network {
        table.insert("network", toml_edit::value(desired.network));
    }
    if current.transport != desired.transport {
        table.insert(
            "transport",
            toml_edit::value(desired.transport.as_str().to_owned()),
        );
    }
    if current.url != desired.url {
        set_optional_string(table, "url", desired.url.as_deref());
    }
    if current.command != desired.command {
        set_optional_string(table, "command", desired.command.as_deref());
    }
    if current.args != desired.args {
        table.insert("args", toml_edit::value(string_array(&desired.args)));
    }
    if current.env != desired.env {
        table.insert("env", toml_edit::value(string_array(&desired.env)));
    }
    if current.enabled != desired.enabled {
        table.insert("enabled", toml_edit::value(desired.enabled));
    }
    if current.agents != desired.agents {
        // Both spellings in one table is a duplicate field, so the legacy key goes.
        table.remove("dots");
        if desired.agents.is_empty() {
            table.remove("agents");
        } else {
            table.insert("agents", toml_edit::value(agents_table(&desired.agents)));
        }
    }
}

/// Set or remove an optional string field.
fn set_optional_string(table: &mut Table, key: &str, value: Option<&str>) {
    match value {
        Some(value) => {
            table.insert(key, toml_edit::value(value.to_owned()));
        }
        None => {
            table.remove(key);
        }
    }
}

/// Build the `toml_edit` array for one string list.
fn string_array(values: &[String]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(value.clone());
    }
    array
}

/// Build the `toml_edit` inline table for one `agents` map.
fn agents_table(agents: &std::collections::BTreeMap<String, Vec<String>>) -> InlineTable {
    let mut table = InlineTable::new();
    for (agent, tools) in agents {
        table.insert(agent.clone(), EditValue::Array(string_array(tools)));
    }
    table
}

/// Build the full `toml_edit` table for a server added to a rewrite.
pub(super) fn server_to_table(server: &McpServerConfig) -> Table {
    let mut table = Table::new();
    table.insert("id", toml_edit::value(server.id.clone()));
    if let Some(catalog_id) = &server.catalog_id {
        table.insert("catalog_id", toml_edit::value(catalog_id.clone()));
    }
    table.insert(
        "data_class",
        toml_edit::value(match server.data_class {
            McpDataClass::Public => "public".to_owned(),
            McpDataClass::Sensitive => "sensitive".to_owned(),
        }),
    );
    table.insert("stdio_confirmed", toml_edit::value(server.stdio_confirmed));
    if let Some(confirmation) = &server.stdio_confirmation {
        table.insert("stdio_confirmation", toml_edit::value(confirmation.clone()));
    }
    if let Some(approval) = &server.approval {
        table.insert("approval", toml_edit::value(approval.clone()));
    }
    table.insert("network", toml_edit::value(server.network));
    table.insert(
        "transport",
        toml_edit::value(server.transport.as_str().to_owned()),
    );
    if let Some(url) = &server.url {
        table.insert("url", toml_edit::value(url.clone()));
    }
    if let Some(command) = &server.command {
        table.insert("command", toml_edit::value(command.clone()));
    }
    if !server.args.is_empty() {
        table.insert("args", toml_edit::value(string_array(&server.args)));
    }
    if !server.env.is_empty() {
        table.insert("env", toml_edit::value(string_array(&server.env)));
    }
    table.insert("enabled", toml_edit::value(server.enabled));
    if !server.agents.is_empty() {
        table.insert("agents", toml_edit::value(agents_table(&server.agents)));
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{McpConfig, McpTransport};

    fn added_server(id: &str) -> McpServerConfig {
        McpServerConfig {
            id: id.to_owned(),
            catalog_id: None,
            data_class: McpDataClass::Sensitive,
            stdio_confirmed: false,
            stdio_confirmation: None,
            approval: None,
            network: false,
            transport: McpTransport::Http,
            url: Some("https://added.invalid/mcp".to_owned()),
            command: None,
            args: vec![],
            env: vec![],
            enabled: false,
            agents: Default::default(),
        }
    }

    #[test]
    fn quarantined_entry_survives_a_confirm_or_revoke_rewrite_verbatim() {
        let bad = "[[server]]\nid = \"bad\"\ntransport = \"carrier-pigeon\"\n";
        let text = format!(
            "[[server]]\nid = \"good\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n\n{bad}"
        );
        let mut config = McpConfig::parse("mcp.toml", &text).unwrap();
        assert_eq!(config.server.len(), 1);
        assert_eq!(config.quarantined.len(), 1);
        assert!(config.quarantined[0].raw.contains("id = \"bad\""));

        // Simulate the confirm endpoint's edit, then a revoke.
        config.server[0].stdio_confirmed = true;
        config.server[0].stdio_confirmation = Some("hash".to_owned());
        let confirmed = config.to_toml_string().unwrap();
        assert!(
            confirmed.contains(bad),
            "the quarantined entry must survive a confirm rewrite: {confirmed:?}"
        );
        assert_eq!(confirmed.matches("[[server]]").count(), 2);

        config.server[0].stdio_confirmed = false;
        config.server[0].stdio_confirmation = None;
        let revoked = config.to_toml_string().unwrap();
        assert!(
            revoked.contains(bad),
            "the quarantined entry must survive a revoke rewrite: {revoked:?}"
        );

        // The rewrite still round-trips: the bad entry stays quarantined.
        let reparsed = McpConfig::parse("mcp.toml", &revoked).unwrap();
        assert_eq!(reparsed.server.len(), 1);
        assert_eq!(reparsed.quarantined.len(), 1);
        assert_eq!(reparsed.quarantined[0].id, "bad");
        assert_eq!(reparsed.quarantined[0].reason, "invalid_transport");

        // An inline non-table element is preserved by the document rewrite too
        // (never dropped, never turned into a second `server = ...` key).
        let odd = McpConfig::parse("t", "server = [\"nope\"]\n").unwrap();
        assert_eq!(odd.quarantined.len(), 1);
        assert_eq!(odd.quarantined[0].reason, "invalid_server");
        let written = odd.to_toml_string().unwrap();
        assert!(written.contains("nope"));
        assert!(!written.contains("server = []"));
    }

    #[test]
    fn a_crlf_file_is_parsed_and_rewritten_without_corruption() {
        let text = "# c\r\n[[server]]\r\nid = \"good\"\r\ntransport = \"http\"\r\n\
                    url = \"https://example.test/mcp\"\r\n\r\n[[server]]\r\n\
                    id = \"bad\"\r\ntransport = \"carrier-pigeon\"\r\n";
        let mut config = McpConfig::parse("mcp.toml", text).unwrap();
        assert_eq!(config.server.len(), 1);
        assert_eq!(config.quarantined.len(), 1);
        config.server[0].enabled = true;
        let written = config.to_toml_string().unwrap();
        assert!(written.contains("# c"));
        assert!(written.contains("transport = \"carrier-pigeon\""));
        let reparsed = McpConfig::parse("mcp.toml", &written).unwrap();
        assert_eq!(reparsed.server.len(), 1);
        assert_eq!(reparsed.quarantined.len(), 1);
        assert_eq!(reparsed.quarantined[0].id, "bad");
        // A CRLF file is normalised to LF on the first rewrite, but rewriting
        // the result again is a byte-for-byte no-op: nothing drifts.
        assert_eq!(reparsed.to_toml_string().unwrap(), written);
    }

    #[test]
    fn a_spaced_server_header_is_parsed_and_rewritten_without_losing_the_entry() {
        let text = "[[ server ]]\nid = \"good\"\ntransport = \"http\"\n\
                    url = \"https://example.test/mcp\"\n\n\
                    [[ server ]]\nid = \"bad\"\ntransport = \"carrier-pigeon\"\n";
        let mut config = McpConfig::parse("mcp.toml", text).unwrap();
        assert_eq!(config.server.len(), 1, "the spaced header is a real entry");
        assert_eq!(config.quarantined.len(), 1);
        config.server[0].enabled = true;
        let written = config.to_toml_string().unwrap();
        // `toml_edit` may normalise the spaced header spelling, but the entry
        // and the quarantined block must survive intact.
        assert!(
            written.contains("[[server]]") || written.contains("[[ server ]]"),
            "the header must still be an array-of-tables header: {written:?}"
        );
        assert!(written.contains("id = \"good\""));
        assert!(written.contains("id = \"bad\""));
        assert!(written.contains("transport = \"carrier-pigeon\""));
        let reparsed = McpConfig::parse("mcp.toml", &written).unwrap();
        assert_eq!(reparsed.server.len(), 1);
        assert_eq!(reparsed.quarantined.len(), 1);
        assert_eq!(reparsed.quarantined[0].reason, "invalid_transport");
    }

    #[test]
    fn a_multiline_string_containing_a_server_header_is_not_a_second_entry() {
        let text = "[[server]]\nid = \"good\"\ntransport = \"stdio\"\n\
                    command = \"/usr/local/bin/tool\"\nargs = [\"\"\"\n[[server]]\nnot an entry\n\"\"\"]\n";
        let mut config = McpConfig::parse("mcp.toml", text).unwrap();
        assert_eq!(config.server.len(), 1, "the string is data, not a header");
        assert!(config.quarantined.is_empty());
        config.server[0].enabled = true;
        let written = config.to_toml_string().unwrap();
        assert_eq!(
            written.matches("[[server]]").count(),
            2,
            "one real header plus the string body: {written:?}"
        );
        let reparsed = McpConfig::parse("mcp.toml", &written).unwrap();
        assert_eq!(reparsed.server.len(), 1);
    }

    #[test]
    fn five_api_cycles_leave_every_untouched_entry_byte_identical() {
        let bad_one = "# keep me\n[[server]]\nid = \"bad-one\"\ntransport = \"carrier-pigeon\"\n";
        let bad_two = "[[server]]\nid = \"bad-two\"\ntransport = \"http\"\n\
                       url = \"http://10.0.0.1/mcp\"\nnetworkk = true\n";
        let stable = "# stable comment\n[[server]]\nid = \"stable\"\ntransport = \"http\"\n\
                      url = \"https://stable.test/mcp\"\n";
        let text = format!(
            "# header comment\n\n[[server]]\nid = \"keep\"\ntransport = \"http\"\n\
             url = \"https://example.test/mcp\"\nenabled = true\n\n\
             [[server]]\nid = \"remove-me\"\ntransport = \"http\"\n\
             url = \"https://two.test/mcp\"\n\n{stable}\n{bad_one}\n{bad_two}"
        );
        let untouched = [bad_one, bad_two, "# header comment\n", stable];
        let mut config = McpConfig::parse("mcp.toml", &text).unwrap();
        assert_eq!(config.server.len(), 3);
        assert_eq!(config.quarantined.len(), 2);

        for cycle in 0..5 {
            match cycle {
                0 => config.server[0].enabled = false,
                1 => {
                    config.server[0].stdio_confirmed = true;
                    config.server[0].stdio_confirmation = Some("binding".to_owned());
                }
                2 => {
                    config.server[0].stdio_confirmed = false;
                    config.server[0].stdio_confirmation = None;
                }
                3 => config.server.retain(|server| server.id != "remove-me"),
                _ => config.server.push(added_server(&format!("added-{cycle}"))),
            }
            let written = config.to_toml_string().unwrap();
            for marker in untouched {
                assert!(
                    written.contains(marker),
                    "cycle {cycle} changed an untouched entry {marker:?}: {written:?}"
                );
            }
            config = McpConfig::parse("mcp.toml", &written).unwrap();
        }
        assert_eq!(config.quarantined.len(), 2);
        assert_eq!(config.quarantined[0].id, "bad-one");
        assert_eq!(config.quarantined[0].reason, "invalid_transport");
        assert_eq!(config.quarantined[1].id, "bad-two");
        assert_eq!(config.quarantined[1].reason, "unknown_key");
        assert!(config.server.iter().any(|server| server.id == "added-4"));
        assert!(config.server.iter().any(|server| server.id == "stable"));
        assert!(!config.server.iter().any(|server| server.id == "remove-me"));
    }
}
