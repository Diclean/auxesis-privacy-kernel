//! Tests for the known-secret scrubber, split by the code they cover.

use super::*;
use std::sync::Mutex;

mod canaries;
mod encodings;
mod escapes;
mod performance;
mod registry;
mod streaming;

/// The registry is process-wide; tests that mutate it take this lock so
/// they never race each other (other test modules only read it, and the
/// values here are unique canaries).
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn unique(tag: &str) -> String {
    // Assembled at runtime; short enough that the secret scanner never
    // sees a vendor-shaped literal.
    format!("CANARY_KS_{tag}_{}", "7f3a9c2e1b5d")
}

/// Independent hex encoder (deliberately not `super::hex_encode`, so a
/// broken fix cannot make the test agree with it).
fn test_hex(value: &str, upper: bool) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    if upper {
        out = out.to_ascii_uppercase();
    }
    out
}

/// Independent base32 (RFC 4648) encoder for the test's own expectations.
fn test_base32(value: &str, pad: bool, lower: bool) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    for chunk in value.as_bytes().chunks(5) {
        let mut buffer = [0u8; 5];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let bits = chunk.len() * 8;
        let symbols = bits.div_ceil(5);
        for index in 0..symbols {
            let mut symbol = 0u8;
            for bit in 0..5 {
                let position = index * 5 + bit;
                let byte = buffer[position / 8];
                let value = (byte >> (7 - position % 8)) & 1;
                symbol = (symbol << 1) | value;
            }
            out.push(ALPHABET[symbol as usize] as char);
        }
    }
    if pad {
        while !out.len().is_multiple_of(8) {
            out.push('=');
        }
    }
    if lower {
        out = out.to_ascii_lowercase();
    }
    out
}

/// `xxd`-shaped dump: offset, hex column, ASCII column.
fn xxd_dump(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::new();
    for (line, chunk) in bytes.chunks(16).enumerate() {
        let mut hex = String::new();
        for (index, byte) in chunk.iter().enumerate() {
            if index > 0 && index % 2 == 0 {
                hex.push(' ');
            }
            hex.push_str(&format!("{byte:02x}"));
        }
        let ascii: String = chunk
            .iter()
            .map(|byte| {
                if (0x20..0x7F).contains(byte) {
                    *byte as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{:08x}: {hex:<39} {ascii}\n", line * 16));
    }
    out
}

/// `hexdump -C`-shaped dump: offset, spaced bytes, piped ASCII column.
fn hexdump_dump(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::new();
    for (line, chunk) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|byte| {
                if (0x20..0x7F).contains(byte) {
                    *byte as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!(
            "{:08x}  {}  |{ascii}|\n",
            line * 16,
            hex.join(" ")
        ));
    }
    out
}

/// `od -A n -t x1`-shaped dump: no offset column, spaced bytes.
fn od_dump(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(16) {
        let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
        out.push_str(&format!(" {}\n", hex.join("  ")));
    }
    out
}
