//! Sanitising and capping one untrusted tool description.

use kernel_broker::sanitize_external_text;

use super::limits::{MAX_DESCRIPTION_BYTES, SANITIZE_BUDGET, TRUNCATION_MARKER};
use super::neutralise::neutralise_server_text;

/// Sanitise an untrusted description and cap it at [`MAX_DESCRIPTION_BYTES`].
///
/// Reuses the shared `kernel-broker` sanitiser (control characters, ANSI escapes,
/// invisible Unicode and every Unicode format character are removed), removes
/// any forged copy of a [`WRAPPER_MARKERS`](super::limits::WRAPPER_MARKERS) token, and then applies a strict
/// byte cap on a character boundary with an explicit truncation marker. The
/// result is always at most [`MAX_DESCRIPTION_BYTES`] bytes, and the operation
/// is idempotent.
pub fn sanitize_description(raw: &str) -> String {
    sanitize_description_capped(raw, MAX_DESCRIPTION_BYTES)
}

fn sanitize_description_capped(raw: &str, max_bytes: usize) -> String {
    let sanitized = sanitize_external_text(raw, SANITIZE_BUDGET);
    // `[truncated]` is a marker [`cap_description`] adds for a hard cap, and
    // nothing else may. A server-supplied copy is peer text and is neutralised
    // by [`neutralise_server_text`] like every other wrapper; only a real cap
    // below appends a fresh one. (The old "carried" branch re-emitted a trailing
    // marker without knowing who wrote it, which let a server fake a truncation
    // notice — Step 5, P3.)
    let neutralised = neutralise_server_text(&sanitized);
    cap_description(&neutralised, max_bytes)
}

/// Cap `cleaned` at [`MAX_DESCRIPTION_BYTES`] with the explicit marker.
fn cap_description(cleaned: &str, max_bytes: usize) -> String {
    if cleaned.len() <= max_bytes {
        return cleaned.to_owned();
    }
    let budget = max_bytes.saturating_sub(TRUNCATION_MARKER.len());
    let mut end = budget.min(cleaned.len());
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{TRUNCATION_MARKER}", &cleaned[..end])
}
