//! Rebuilding a model-visible schema from typed input.

use serde_json::{Map, Value};

use super::limits::{MAX_SCHEMA_BYTES, MAX_SCHEMA_DEPTH};
use crate::tools::ToolSchema;

/// Rebuild a model-visible schema from the typed schema using a structural
/// allowlist. Free-form prose and unknown keywords never leave this boundary.
/// Invalid property/keyword names reject the whole tool instead of being
/// normalised into a different name.
pub fn sanitize_schema(schema: &ToolSchema) -> Option<Value> {
    let cleaned = rebuild_schema_node(schema.as_value(), 0)?;
    (serde_json::to_vec(&cleaned).map_or(usize::MAX, |bytes| bytes.len()) <= MAX_SCHEMA_BYTES)
        .then_some(cleaned)
}

fn rebuild_schema_node(value: &Value, depth: usize) -> Option<Value> {
    if depth > MAX_SCHEMA_DEPTH {
        return None;
    }
    if let Value::Bool(schema) = value {
        return Some(Value::Bool(*schema));
    }
    let Value::Object(input) = value else {
        return None;
    };
    let mut output = Map::new();
    for (keyword, value) in input {
        if !valid_schema_identifier(keyword) {
            return None;
        }
        let rebuilt = match keyword.as_str() {
            "type" => rebuild_type(value),
            "properties" => Some(rebuild_properties(value, depth + 1)?),
            "required" => Some(rebuild_required(value)?),
            "items" => match value {
                Value::Bool(value) => Some(Value::Bool(*value)),
                Value::Object(_) => Some(rebuild_schema_node(value, depth + 1)?),
                _ => None,
            },
            "enum" => rebuild_enum(value),
            "minimum" | "maximum" => value.is_number().then(|| value.clone()),
            "minLength" | "maxLength" | "minItems" | "maxItems" => {
                value.as_u64().map(|number| Value::Number(number.into()))
            }
            "additionalProperties" => value.as_bool().map(Value::Bool),
            "format" => value
                .as_str()
                .filter(|format| allowed_format(format))
                .map(|format| Value::String(format.to_owned())),
            // Descriptions, titles, defaults, examples, refs, vendor extensions
            // and all unknown keywords are intentionally omitted.
            _ => None,
        };
        if let Some(value) = rebuilt {
            output.insert(keyword.clone(), value);
        }
    }
    Some(Value::Object(output))
}

fn rebuild_type(value: &Value) -> Option<Value> {
    fn valid_type(value: &Value) -> bool {
        matches!(
            value.as_str(),
            Some("object" | "array" | "string" | "number" | "integer" | "boolean" | "null")
        )
    }
    match value {
        Value::String(_) if valid_type(value) => Some(value.clone()),
        Value::Array(items) if !items.is_empty() && items.iter().all(valid_type) => {
            Some(value.clone())
        }
        _ => None,
    }
}

fn rebuild_properties(value: &Value, depth: usize) -> Option<Value> {
    let Value::Object(properties) = value else {
        return None;
    };
    let mut output = Map::new();
    for (name, schema) in properties {
        if !valid_schema_identifier(name) {
            return None;
        }
        output.insert(name.clone(), rebuild_schema_node(schema, depth)?);
    }
    Some(Value::Object(output))
}

fn rebuild_required(value: &Value) -> Option<Value> {
    let Value::Array(names) = value else {
        return None;
    };
    if names
        .iter()
        .all(|name| name.as_str().is_some_and(valid_schema_identifier))
    {
        Some(value.clone())
    } else {
        None
    }
}

fn rebuild_enum(value: &Value) -> Option<Value> {
    let Value::Array(values) = value else {
        return None;
    };
    // All or nothing: a partially filtered enum would silently change the
    // tool's contract, so one unsafe value drops the whole list (the server
    // still validates its own input).
    let all_safe = !values.is_empty()
        && values.len() <= MAX_ENUM_VALUES
        && values.iter().all(|value| match value {
            Value::String(text) => safe_enum_text(text),
            Value::Number(_) | Value::Bool(_) | Value::Null => true,
            Value::Array(_) | Value::Object(_) => false,
        });
    all_safe.then(|| Value::Array(values.clone()))
}

fn valid_schema_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Most enum values a rebuilt schema keeps; a longer list is dropped.
const MAX_ENUM_VALUES: usize = 32;

/// An enum string is a short token, never prose: no spaces, so a server cannot
/// smuggle a sentence ("ignore previous instructions …") into the schema the
/// model reads.
fn safe_enum_text(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn allowed_format(value: &str) -> bool {
    matches!(
        value,
        "date"
            | "time"
            | "date-time"
            | "duration"
            | "email"
            | "hostname"
            | "ipv4"
            | "ipv6"
            | "uuid"
            | "uri"
    )
}
