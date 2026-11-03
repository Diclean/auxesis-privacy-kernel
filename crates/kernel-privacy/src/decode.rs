//! Pre-processing with an exact offset map back to the original bytes.
//!
//! Messy e-mail reaches the kernel through HTML-to-text conversions and link
//! rewriting, so a value the deterministic recognisers would catch in clear
//! text arrives encoded:
//!
//! * HTML entities (`&nbsp;`, `&amp;`, `&#39;`, `&#x27;`, `&eacute;`) split a
//!   value or hide its separators;
//! * percent escapes inside a URL (`freya.halloran%40example.invalid`,
//!   `nom=Oc%C3%A9ane+Mabille`) hide the address or the name;
//! * a URL packs a path and query into one token whose `-`, `_`, `.`, `+`
//!   separators the detectors must treat as word breaks.
//!
//! [`DecodedText`] builds a decoded view of the input and keeps, for every
//! character of that view, the original byte range it came from. A detection
//! runs on the decoded view; its span is mapped back with
//! [`DecodedText::source_bounds`] and the caller verifies the bytes as usual.
//! Percent escapes are decoded only inside a token that carries a URL scheme,
//! so a stray `%40` in prose is not silently turned into an address; named
//! entities are decoded everywhere because they are unambiguous.
//!
//! The view is for detection: token markers (`⟦…⟧`, a lone bracket) and
//! default-ignorable characters (zero-width space, soft hyphen) are dropped and
//! their bytes go to the next character, so `sk-ab⟦T⟧cd` reads `sk-abcd`.
//!
//! The module also exposes [`DecodedText::url_segments`], which walks the URLs
//! of the source and yields their path and query values split into scannable
//! segments with their original byte offsets.

// The submodules are private on purpose: every item below is re-exported at
// this path, so `crate::decode::…` is exactly what it was before the split,
// and no new public path appears.
mod entities;
mod escapes;
mod html_entities;
mod limits;
mod pass;
mod view;

#[cfg(test)]
mod tests;

pub use escapes::known_escape_at;
pub use limits::{MAX_PASSES, MAX_SECRET_DECODE_WORK};
pub use pass::url_ranges;
pub use view::DecodedText;

pub(crate) use html_entities::MAX_ENTITY_BODY;
pub(crate) use limits::tokens_still_encoded;
