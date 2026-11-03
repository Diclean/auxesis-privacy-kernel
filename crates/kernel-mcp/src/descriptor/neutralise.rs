//! Neutralising the wrapper markers a hostile server could impersonate.

use super::forged_provenance::neutralise_forged_provenance;
use super::limits::WRAPPER_MARKERS;

/// Neutralise every wrapper a hostile server could impersonate in peer text.
///
/// A forged provenance tag — any case, spacing, homoglyph or line-split variant
/// — has its whole line replaced by
/// [`FORGED_PROVENANCE_MARKER`](super::limits::FORGED_PROVENANCE_MARKER), and a
/// forged bracketed `[truncated…]` run is dropped. This is the one entry point
/// the descriptor, the call-result text and the protocol-error sanitiser share,
/// so no path can re-emit a server-written wrapper.
pub(crate) fn neutralise_server_text(text: &str) -> String {
    neutralise_wrapper_markers(&neutralise_forged_provenance(text))
}

/// Remove any occurrence of a [`WRAPPER_MARKERS`] token from peer text.
///
/// The whole bracketed run is dropped, so a hostile server cannot put
/// `[truncated: …]` in a description and make it indistinguishable from a
/// wrapper Auxesis itself added. Removing the run is idempotent: a second pass
/// finds nothing left to strip.
pub(super) fn neutralise_wrapper_markers(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = earliest_wrapper_marker(rest) {
        out.push_str(&rest[..start]);
        let run = &rest[start..];
        match run.find(']') {
            Some(close) => rest = &run[close + 1..],
            // An unterminated marker run is dropped to the end: it can only
            // ever remove peer text, never smuggle a marker through.
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The earliest occurrence of any [`WRAPPER_MARKERS`] token in `text`.
fn earliest_wrapper_marker(text: &str) -> Option<usize> {
    WRAPPER_MARKERS
        .iter()
        .filter_map(|marker| text.find(marker))
        .min()
}
