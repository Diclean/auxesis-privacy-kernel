//! Title and display scrubbing: runs the standard Private-mode detector
//! and replaces each detected value with a short neutral label.

use std::sync::OnceLock;

use kernel_core::text::truncate_chars;
use kernel_privacy::safetext::{Detector, StandardDetector};
use kernel_privacy::EntityKind;

use super::*;

/// The most characters of a candidate title the detector scans. Display caps
/// smaller than this (the 60-character chat title) run after detection.
const TITLE_SCAN_CHARS: usize = 400;

/// The most characters a scrubbed title returns. Detection has already seen
/// the full 400-character scan, so this display cap cannot expose a prefix.
const TITLE_RETURN_CHARS: usize = 200;

/// Byte cap after labels and sanitising: 400 characters are at most 1600 UTF-8
/// bytes, and the labels add a little.
const TITLE_SCRUB_BYTES: usize = 4096;

/// Written instead of a title when detection itself fails: a title is display
/// text, so the failure is closed, never the raw line.
const TITLE_HIDDEN: &str = "[title hidden]";

/// Written instead of display text when detection itself fails.
const DISPLAY_HIDDEN: &str = "[content hidden]";

/// The one detector shared by every scrub. It is the same standard set a
/// Private-mode gate runs: e-mail, phone, IBAN, payment card, national IDs,
/// health terms, secrets and the rest of the deterministic registry.
fn title_detector() -> &'static StandardDetector {
    static DETECTOR: OnceLock<StandardDetector> = OnceLock::new();
    DETECTOR.get_or_init(StandardDetector::new)
}

/// The short neutral label a title shows in place of one detected value, or
/// `None` when the value stays readable: the owner's rule keeps every name
/// visible.
fn title_label(kind: EntityKind) -> Option<&'static str> {
    Some(match kind {
        EntityKind::Email => "[e-mail]",
        EntityKind::Phone => "[phone]",
        EntityKind::Iban => "[IBAN]",
        EntityKind::CreditCard => "[card]",
        // A link or a bare IP is not one of the PII classes a title or a
        // preview hides; a value inside one (an e-mail in a URL) is still its
        // own span and is labelled above it.
        EntityKind::IpV4 | EntityKind::Url => return None,
        EntityKind::FrNir
        | EntityKind::FrSiret
        | EntityKind::HuTaj
        | EntityKind::HuTaxId
        | EntityKind::ZaId
        | EntityKind::UkNino
        | EntityKind::PassportMrz
        | EntityKind::NationalId => "[ID]",
        EntityKind::FrSiren | EntityKind::FrVat => "[company ID]",
        EntityKind::Address => "[address]",
        EntityKind::DateOfBirth => "[date of birth]",
        EntityKind::Health => "[health]",
        EntityKind::Religion => "[religion]",
        EntityKind::SexualOrientation => "[orientation]",
        EntityKind::Union => "[union]",
        EntityKind::Ethnicity => "[ethnicity]",
        EntityKind::Secret => "[secret]",
        EntityKind::Person | EntityKind::Organization => return None,
    })
}

/// Every detected non-name value in `text` replaced by its neutral label.
/// `None` means detection failed or returned a malformed span: callers fail
/// closed with their own fixed text. `include_secret` is off for display
/// text that already ran the secret scrubber: keeping its `<redacted>` marker
/// (and its established false positives) beats relabelling it `[secret]`.
fn label_detected(text: &str, include_secret: bool) -> Option<String> {
    let mut spans = title_detector().detect(text).ok()?;
    spans.sort_by_key(|span| (span.start, span.end));
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for span in spans {
        if span.kind == EntityKind::Secret && !include_secret {
            continue;
        }
        let Some(label) = title_label(span.kind) else {
            continue;
        };
        if span.start < copied
            || span.end > text.len()
            || !text.is_char_boundary(span.start)
            || !text.is_char_boundary(span.end)
        {
            return None;
        }
        out.push_str(&text[copied..span.start]);
        out.push_str(label);
        copied = span.end;
    }
    out.push_str(&text[copied..]);
    Some(out)
}

/// The title line of `text` with every detected value replaced by its short
/// neutral label: the first line, scanned up to 400 characters **before**
/// detection, then capped at 200 characters for display.
///
/// The detector is the same set Private mode runs, so an e-mail, phone, IBAN,
/// card, national ID, health term or secret typed as the first line never
/// becomes a chat title. Names are left visible on purpose (owner rule).
/// Detection failure yields `TITLE_HIDDEN`, never the raw line. If the scan
/// cap would cut through a run with no whitespace, the whole run is dropped and
/// an ellipsis marks the cut: a partial candidate is never detected as text.
pub fn scrub_title(text: &str) -> String {
    let first = text.lines().next().unwrap_or("").trim();
    let chars: Vec<char> = first.chars().collect();
    let cut = chars.len() > TITLE_SCAN_CHARS;
    let mut scan: String = chars.iter().take(TITLE_SCAN_CHARS).collect();
    if cut && !scan.chars().last().is_some_and(char::is_whitespace) {
        // The cap fell inside a non-whitespace run. Drop the run: its start
        // may be a value whose tail (the detector would need) is past the cap.
        match scan.rfind(char::is_whitespace) {
            Some(at) => scan.truncate(at),
            None => scan.clear(),
        }
    }
    // Detect on the bytes a reader would see: an ANSI sequence must not split
    // an address the sanitiser would later join back together.
    let bounded = sanitize_external_text_keep_isolates(&scan, TITLE_SCRUB_BYTES);
    let mut out = if bounded.is_empty() {
        String::new()
    } else {
        label_detected(&bounded, true).unwrap_or_else(|| TITLE_HIDDEN.to_string())
    };
    if cut {
        out.push('…');
    }
    truncate_chars(&out, TITLE_RETURN_CHARS)
}

/// Full-detector scrub for display text that is not a single title: every
/// detected non-name value gets its neutral label before the caller collapses
/// lines or caps the result. Secret spans are left to the caller's established
/// secret scrubber, which keeps its `<redacted>` marker. Detection failure
/// yields `DISPLAY_HIDDEN`.
pub fn scrub_display_text(text: &str, max_bytes: usize) -> String {
    let clean = sanitize_external_text_keep_isolates(text, max_bytes);
    match label_detected(&clean, false) {
        Some(out) => redact_secrets(&out),
        None => DISPLAY_HIDDEN.to_string(),
    }
}
