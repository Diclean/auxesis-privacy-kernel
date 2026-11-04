//! Text hygiene for untrusted content entering the model context or the
//! terminal.
//!
//! Tool outputs, provider errors and model text are all *external* input:
//! they can contain ANSI escapes, bidi overrides and zero-width characters
//! that spoof what a human sees, and they can be arbitrarily large. These
//! helpers strip the invisible characters and cap the size.
//!
//! [`sanitize_error_detail`] and [`scrub_external_preview`] are the shared
//! presentation scrubbers: the daemon API, the CLI and the app render
//! upstream error strings through them, so no transport error (which may be
//! attacker-influenced) can forge terminal output or carry key-shaped
//! strings.

use std::path::Path;

pub use kernel_core::text::sanitize_text;
use kernel_core::text::truncate_chars;

use secrets::normalise_for_scrub;

mod echo;
mod identifiers;
mod json;
mod log;
mod names;
mod redactor;
mod secrets;
mod shapes;
mod title;

pub use echo::{classify_echo, is_secret_shaped, EchoState};
pub use identifiers::redact_identifiers;
pub use json::scrub_json_value;
pub use log::{guard_log_redaction, redact_log_line, redact_log_line_guarded};
pub use secrets::redact_secrets;
pub use title::{scrub_display_text, scrub_title};

pub(crate) use names::{
    classify_name, header_gate, is_run_byte, vendor_prefix, HeaderGate, NameInfo, Strength,
};

// The text module's tests drive the private identifier helpers directly;
// keep those two names on the test-only path, not the crate one.
#[cfg(test)]
use identifiers::{redact_grouped_phone_numbers, redact_jid_identifiers};

/// Marker that replaces one redacted value. The key, its separator and every
/// structural byte around the value are re-emitted unchanged: redaction
/// replaces the value only.
pub(crate) const MASK: &str = "<redacted>";

/// Bounded window (bytes) the pair scanner may skip between a separator and
/// its value: spaces, tabs, line breaks, indentation and one shell line
/// continuation. Bounded so the skip can never go quadratic.
pub(crate) const PAIR_SKIP_LIMIT: usize = 256;

/// Bounded window (bytes) the quoted-value scan looks across for a closing
/// quote, so a value broken over lines is one value without ever rescanning
/// the document.
pub(crate) const QUOTED_SCAN_LIMIT: usize = 1024;

/// Scrub an upstream error string before it is echoed to the owner.
///
/// Deliberately conservative: control and invisible characters are stripped
/// (a message must never contain ANSI escapes or bidi tricks), the Auxesis
/// `home` path is replaced by `<home>`, every documented **plain-text**
/// secret shape is redacted by [`redact_secrets`] (defense in depth: no key
/// material in an error), and the result is collapsed to one line and capped
/// at `max_chars` characters. Pattern redaction cannot see values that are
/// base64/hex/line-split before they reach the text; see [`redact_secrets`].
pub fn sanitize_error_detail(home: &Path, text: &str, max_chars: usize) -> String {
    // Known values first: redact before the cap, so a truncation can never
    // leave half a resolved key in the message.
    let known = super::scrub::redact_known_secrets(text);
    let text: &str = known.as_deref().unwrap_or(text);
    // Normalise next: an ANSI sequence between a name and its separator must
    // be dropped as a unit *before* the plain sanitiser leaves its residue
    // (`api_key[0m=…`); L0 in `redact_secrets` would arrive too late.
    let normalised = normalise_for_scrub(text);
    let cleaned = sanitize_external_text(&normalised, max_chars * 4);
    let home = home.display().to_string();
    let cleaned = if home.is_empty() {
        cleaned
    } else {
        cleaned.replace(&home, "<home>")
    };
    let cleaned = redact_secrets(&cleaned);
    let collapsed: String = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&collapsed, max_chars)
}

/// Scrub one tool-visible preview string (arguments, result): sanitize
/// control/invisible characters, replace the Auxesis home path with
/// `<home>`, redact every documented secret shape via [`redact_secrets`],
/// and cap the result.
///
/// Same transformations as [`sanitize_error_detail`] minus the one-line
/// collapse: a preview may legitimately span lines (a command, a diff).
pub fn scrub_external_preview(home: &Path, text: &str, max_bytes: usize) -> String {
    // Known values first (same reason as `sanitize_error_detail`): a
    // truncation must never cut a resolved key before it is redacted.
    let known = super::scrub::redact_known_secrets(text);
    let base: &str = known.as_deref().unwrap_or(text);
    // If the heuristic layers find nothing to redact either, nothing in this
    // text hides a secret: keep the bytes that are content, including the
    // bidi isolate controls the scanning normaliser strips (dh-1 fidelity
    // note). Anything else (ANSI, other invisibles) is still sanitised.
    let redacted = redact_secrets(base);
    if redacted == base {
        let cleaned = sanitize_external_text_keep_isolates(base, max_bytes);
        let cleaned = replace_home(cleaned, home);
        return redact_secrets(&cleaned);
    }
    // Something was redacted: the normalised/masked text is the
    // authoritative one, and the same ordering as before applies (mask
    // before the cap so a truncation cannot cut a key into view; scrub again
    // after the cap for a secret the head/tail cut may have completed).
    let cleaned = sanitize_external_text(&redacted, max_bytes);
    let cleaned = replace_home(cleaned, home);
    redact_secrets(&cleaned)
}

/// Written in place of a log line whose redaction panicked. The text is
/// fixed, so no part of the raw line can reach the log.
pub const REDACTION_ERROR_LINE: &str = "<redaction-error: line dropped>";

/// Drop ANSI CSI (`ESC [ … final`) and OSC (`ESC ] … BEL`) sequences whole.
///
/// The plain sanitiser strips the ESC byte and leaves the CSI parameters
/// (`api_key[0m=…`); removing the sequence as a unit keeps the pair
/// scannable for every later layer.
fn strip_ansi(text: &str) -> String {
    if !text.contains('\u{1b}') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some('[') => {
                chars.next();
                for next in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&next) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                for next in chars.by_ref() {
                    if next == '\u{7}' {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Sanitize and cap `input` at `max_bytes`, keeping the head **and** the tail
/// (exit codes and error lines live at the end) and marking the cut.
///
/// The cut is made on UTF-8 char boundaries; `max_bytes` is a soft floor as
/// the marker line adds bytes.
pub fn sanitize_external_text(input: &str, max_bytes: usize) -> String {
    cap_head_and_tail(sanitize_text(&strip_ansi(input)), max_bytes)
}

/// [`sanitize_external_text`] that keeps the four bidi isolate controls
/// (U+2066–U+2069): the scrub preview path uses it so secret-free text keeps
/// them byte-for-byte (dh-1 fidelity note). Every other control/invisible
/// character, ANSI escapes included, is still removed.
fn sanitize_external_text_keep_isolates(input: &str, max_bytes: usize) -> String {
    cap_head_and_tail(
        kernel_core::text::sanitize_text_keep_bidi_isolates(&strip_ansi(input)),
        max_bytes,
    )
}

/// Replace the Auxesis home path with `<home>` when there is one.
fn replace_home(cleaned: String, home: &Path) -> String {
    if home.as_os_str().is_empty() || cleaned.is_empty() {
        cleaned
    } else {
        cleaned.replace(&home.display().to_string(), "<home>")
    }
}

/// Keep the head **and** the tail of `cleaned`, marking the cut at
/// `max_bytes` (a soft floor: the marker line adds bytes).
fn cap_head_and_tail(cleaned: String, max_bytes: usize) -> String {
    if cleaned.len() <= max_bytes {
        return cleaned;
    }
    let total = cleaned.len();
    let head_budget = max_bytes * 3 / 4;
    let tail_budget = max_bytes - head_budget;
    let mut head_end = head_budget;
    while head_end > 0 && !cleaned.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = total - tail_budget;
    while tail_start < total && !cleaned.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    let kept_tail = total - tail_start;
    format!(
        "{}\n[truncated: showing first {head_end} and last {kept_tail} of {total} bytes]\n{}",
        &cleaned[..head_end],
        &cleaned[tail_start..]
    )
}

#[cfg(test)]
mod tests;
