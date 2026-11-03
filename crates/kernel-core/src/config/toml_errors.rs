//! Redacted, position-only text for TOML parse errors.

/// Rebuild a TOML parse error so it names the file, line and column and
/// never quotes the document.
///
/// toml 0.9 prints the offending source line in `Display` and keeps the whole
/// document in `Debug`, and serde's messages quote field names, variants and
/// values taken from the file, so a key pasted on a broken line or typed as a
/// key would reach logs, API errors and the CLI. The returned error carries
/// only `file`, the 1-based line and column of the error's span over
/// `source`, and a fixed generic kind ([`toml_error_kind`]). Its `Display` and
/// `Debug` hold nothing else.
pub fn redact_toml_error(err: &toml::de::Error, file: &str, source: &str) -> toml::de::Error {
    let message = describe_toml_error(file, source, err.span(), err.message());
    <toml::de::Error as serde::de::Error>::custom(message)
}

/// [`redact_toml_error`] for any parser that gives a span and a message
/// (`toml_edit` renders the source line the same way). An empty `file`
/// leaves just the position and kind. No text of `message` is copied.
pub fn describe_toml_error(
    file: &str,
    source: &str,
    span: Option<std::ops::Range<usize>>,
    message: &str,
) -> String {
    let mut out = file.to_string();
    if let Some(span) = span {
        let before = &source.as_bytes()[..span.start.min(source.len())];
        let line_start = before
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |at| at + 1);
        let line = before.iter().filter(|b| **b == b'\n').count() + 1;
        let column = std::str::from_utf8(&before[line_start..])
            .map_or(before.len() - line_start, |text| text.chars().count())
            + 1;
        let sep = if out.is_empty() { "" } else { ", " };
        out.push_str(&format!("{sep}line {line}, column {column}"));
    }
    out.push_str(if out.is_empty() { "" } else { ": " });
    out.push_str(toml_error_kind(message));
    out
}

/// A fixed kind for a TOML/serde error message. Only the message's leading
/// words are matched, and only a constant is returned: the field names,
/// variants and values serde quotes never come through.
pub fn toml_error_kind(message: &str) -> &'static str {
    const KINDS: [(&str, &str); 8] = [
        ("unknown field", "unknown field"),
        ("unknown variant", "unknown value"),
        ("invalid type", "wrong type"),
        ("invalid value", "invalid value"),
        ("invalid length", "wrong length"),
        ("missing field", "missing field"),
        ("duplicate", "duplicate key"),
        ("missing", "missing value"),
    ];
    let message = message.trim_start();
    KINDS
        .iter()
        .find(|(prefix, _)| message.starts_with(prefix))
        .map_or("syntax error", |(_, kind)| kind)
}
