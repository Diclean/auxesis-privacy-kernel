//! Tests for the argument screen, split by the code they cover.

/// Lowercase hex of `text`, one byte at a time.
fn hex(text: &str) -> String {
    text.bytes().map(|byte| format!("{byte:02x}")).collect()
}

/// `text` percent-encoded `layers` times: every byte but a letter or a digit
/// in the first layer, so each later layer escapes only the `%` signs.
fn percent_layers(text: &str, layers: usize) -> String {
    (0..layers).fold(text.to_string(), |text, _| {
        text.bytes()
            .map(|byte| match byte {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => char::from(byte).to_string(),
                _ => format!("%{byte:02X}"),
            })
            .collect()
    })
}

mod caps;
mod decode;
mod performance;
mod phone;
mod residue;
mod screen;
mod shapes;
mod views;
