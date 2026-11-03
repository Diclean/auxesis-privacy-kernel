//! Log-line redaction: the shared secret and identity scrubbers, with a
//! panic guard that drops a line rather than ever write it raw.

use super::*;

/// The log-line redactor: the shared secret scrubber ([`redact_secrets`])
/// then the identity scrubber ([`redact_identifiers`]). Every writer the
/// daemon and the app's WhatsApp crate install runs formatted records through this.
pub fn redact_log_line(text: &str) -> String {
    redact_identifiers(&redact_secrets(text))
}

/// [`redact_log_line`] for the log writers. A redaction bug must never crash
/// the writer, and a line that cannot be redacted is replaced by
/// `REDACTION_ERROR_LINE`, never written raw. A caught panic reports only its
/// source location: the process hook is payload-free.
pub fn redact_log_line_guarded(text: &str) -> String {
    guard_log_redaction(text, redact_log_line)
}

/// Run `redact` on `text` behind the log guard. [`redact_log_line_guarded`] is
/// this with [`redact_log_line`]; the redaction step is a parameter so the
/// panic path can be driven from other crates' tests.
pub fn guard_log_redaction(text: &str, redact: impl FnOnce(&str) -> String) -> String {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| redact(text)))
        .unwrap_or_else(|_| REDACTION_ERROR_LINE.to_string())
}
