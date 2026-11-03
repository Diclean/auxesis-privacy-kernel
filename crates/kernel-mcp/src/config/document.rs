//! Reading `[[server]]` entries out of a parsed `toml_edit` document.

use toml_edit::{DocumentMut, InlineTable, Item, Table, Value as EditValue};

use super::model::invalid;
use super::{McpConfigError, McpServerConfig, McpTransport};

/// The keys a `[[server]]` entry may carry (mirrors `McpServerConfig`).
const SERVER_ENTRY_KEYS: &[&str] = &[
    "id",
    "catalog_id",
    "data_class",
    "stdio_confirmed",
    "stdio_confirmation",
    "network",
    "transport",
    "url",
    "command",
    "args",
    "env",
    "enabled",
    "agents",
    // Legacy spelling of `agents`, still accepted on read.
    "dots",
];

/// One `server` entry recovered from the parsed document.
pub(super) struct DocumentEntry {
    /// The entry as a plain `toml::Value`, for the per-entry deserialization.
    pub(super) value: toml::Value,
    /// Best-effort TOML rendering, for `QuarantinedServer::raw`.
    pub(super) raw: String,
}

/// Every `server` entry of the document, in file order.
///
/// Both the documented `[[server]]` array of tables and the inline
/// `server = [ { ... } ]` form are accepted; anything else is a whole-file
/// error (as before).
pub(super) fn document_server_entries(
    document: &DocumentMut,
) -> Result<Vec<DocumentEntry>, McpConfigError> {
    let Some(item) = document.as_table().get("server") else {
        return Ok(Vec::new());
    };
    match item {
        Item::ArrayOfTables(array) => Ok(array
            .iter()
            .map(|table| DocumentEntry {
                value: table_to_value(table),
                raw: format!("[[server]]\n{table}"),
            })
            .collect()),
        Item::Value(EditValue::Array(entries)) => Ok(entries
            .iter()
            .map(|value| DocumentEntry {
                value: edit_value_to_value(value),
                raw: value.to_string(),
            })
            .collect()),
        _ => Err(invalid("`server` must be an array of tables")),
    }
}

/// The best-effort `id` of one parsed entry, when it carries a string one.
pub(super) fn entry_id(entry: &toml::Value) -> Option<String> {
    entry
        .get("id")
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
}

/// The best-effort transport of one parsed entry, when it names a valid one.
pub(super) fn entry_transport(entry: &toml::Value) -> Option<McpTransport> {
    match entry.get("transport").and_then(toml::Value::as_str) {
        Some("http") => Some(McpTransport::Http),
        Some("stdio") => Some(McpTransport::Stdio),
        _ => None,
    }
}

/// Validate one `[[server]]` entry on its own, without the duplicate rule.
///
/// The entry is inspected as a `toml::Value` first so a precise, content-free
/// label names the failure; only then is it deserialized.
pub(super) fn validate_server_entry(item: &toml::Value) -> Result<McpServerConfig, &'static str> {
    let Some(table) = item.as_table() else {
        return Err("invalid_server");
    };
    for key in table.keys() {
        if !SERVER_ENTRY_KEYS.contains(&key.as_str()) {
            return Err("unknown_key");
        }
    }
    match table.get("transport").and_then(toml::Value::as_str) {
        Some("http") | Some("stdio") => {}
        Some(_) => return Err("invalid_transport"),
        None => return Err("missing_transport"),
    }
    if table
        .get("data_class")
        .is_some_and(|class| !matches!(class.as_str(), Some("public") | Some("sensitive")))
    {
        return Err("invalid_data_class");
    }
    item.clone()
        .try_into::<McpServerConfig>()
        .map_err(|_| "invalid_server")
}

/// Render one `toml_edit` table (or every value under it) as a plain
/// `toml::Value`, so the shared per-entry deserialization applies unchanged.
pub(super) fn table_to_value(table: &Table) -> toml::Value {
    let mut map = toml::map::Map::new();
    for (key, item) in table.iter() {
        if let Some(value) = item_to_value(item) {
            map.insert(key.to_owned(), value);
        }
    }
    toml::Value::Table(map)
}

/// Render one `toml_edit` value as a plain `toml::Value`.
fn edit_value_to_value(value: &EditValue) -> toml::Value {
    match value {
        EditValue::String(string) => toml::Value::String(string.value().clone()),
        EditValue::Integer(integer) => toml::Value::Integer(*integer.value()),
        EditValue::Float(float) => toml::Value::Float(*float.value()),
        EditValue::Boolean(boolean) => toml::Value::Boolean(*boolean.value()),
        // A datetime never appears in a server entry; keep it as a string so an
        // unparsable field is refused rather than silently accepted.
        EditValue::Datetime(datetime) => toml::Value::String(datetime.value().to_string()),
        EditValue::Array(array) => {
            toml::Value::Array(array.iter().map(edit_value_to_value).collect())
        }
        EditValue::InlineTable(table) => toml::Value::Table(inline_table_to_map(table)),
    }
}

/// Render one `toml_edit` item as a plain `toml::Value`, when it has one.
fn item_to_value(item: &Item) -> Option<toml::Value> {
    match item {
        Item::None => None,
        Item::Value(value) => Some(edit_value_to_value(value)),
        Item::Table(table) => Some(table_to_value(table)),
        Item::ArrayOfTables(array) => Some(toml::Value::Array(
            array.iter().map(table_to_value).collect(),
        )),
    }
}

/// Render one inline table as a plain `toml::Value` map.
pub(super) fn inline_table_to_map(table: &InlineTable) -> toml::map::Map<String, toml::Value> {
    let mut map = toml::map::Map::new();
    for (key, value) in table.iter() {
        map.insert(key.to_owned(), edit_value_to_value(value));
    }
    map
}
