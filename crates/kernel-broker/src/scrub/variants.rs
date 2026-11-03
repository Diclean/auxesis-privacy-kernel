//! The spelling closure of one registered value: the transform set, the
//! depth-2 composition and the per-value budget that marks it fail-closed.

use std::collections::BTreeSet;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use unicode_normalization::UnicodeNormalization;

use super::encodings::{
    base32_encode, braced_unicode_escaped, escaped_hex, hex_encode, hex_separated, hex_zero_x,
    html_entities, percent_encode, percent_encode_all, percent_encode_minimal, unicode_escaped,
    uppercase_unicode_escapes,
};
use super::fold::is_scrub_noise;
use super::*;

/// Every searchable form of one secret: the value itself, its hex spelling
/// (raw, `\xNN`-escaped, dump-separated — SB6-01), percent-encoded (both hex
/// cases), JSON-escaped, base64 (standard and URL-safe, padded and unpadded),
/// base32 (RFC 4648, padded and unpadded), the whole-value case folds and the
/// whitespace/zero-width-condensed form of each.
/// Every needle spelling of one value, plus whether the closure could not be
/// covered completely (a spelling over [`MAX_VARIANT_LEN`], or a depth-2
/// closure over its byte budget; R10: the caller then marks the value
/// fail-closed).
pub(super) fn secret_variants(value: &str) -> (BTreeSet<String>, bool) {
    let mut variants = BTreeSet::new();
    // A spelling longer than `MAX_VARIANT_LEN` is a mainstream spelling the
    // registry cannot cover: the value is flagged fail-closed.
    let oversized = std::cell::Cell::new(false);
    let mut push = |variant: String| {
        if variant.len() >= MIN_KNOWN_SECRET_LEN {
            if variant.len() <= MAX_VARIANT_LEN {
                variants.insert(variant);
            } else {
                oversized.set(true);
            }
        }
    };
    // The secret and its whole-value case folds: Aho-Corasick is byte-exact,
    // so a log shipper or DB that lowercases text must not defeat the layer
    // (SB6-03). `to_lowercase`/`to_uppercase` are only added when they differ
    // (a no-op copy would just bloat the automaton).
    let mut bases: Vec<String> = vec![value.to_string()];
    // R8: the value's own NFKC form is a needle too, so a registered value
    // containing a ligature or compatibility character still matches the
    // plain spelling (and vice versa through the folded scan).
    let nfkc: String = value.nfkc().collect();
    if nfkc != value && !bases.contains(&nfkc) {
        bases.push(nfkc);
    }
    for folded in [value.to_lowercase(), value.to_uppercase()] {
        if folded != value && !bases.contains(&folded) {
            bases.push(folded);
        }
    }
    // R9: spellings are a composition closure of the transform set, not a
    // fixed list. The primary base gets depth 2 (every pair of transforms:
    // base64-of-hex, hex-of-base64, percent-of-base64, percent-of-hex, …);
    // case folds keep depth 1, and the whole closure is budgeted per value.
    // Exceeding the budget degrades to depth 1 and flags the value
    // fail-closed.
    for (index, base) in bases.iter().enumerate() {
        push(base.clone());
        let mut depth1: Vec<String> = Vec::new();
        for kind in TRANSFORMS.iter() {
            if let Some(variant) = apply_transform(*kind, base) {
                if variant.len() <= MAX_VARIANT_LEN {
                    depth1.push(variant);
                } else {
                    oversized.set(true);
                }
            }
        }
        for variant in &depth1 {
            push(variant.clone());
        }
        // The escaped/braced spellings stay available at depth 1 for every
        // base (`\U00000043`, `\u{43}`, `\u{0043}`).
        push(unicode_escaped(base, "\\U", false));
        push(unicode_escaped(base, "\\U", true));
        for digits in [2usize, 4, 6] {
            push(braced_unicode_escaped(base, digits, false));
            push(braced_unicode_escaped(base, digits, true));
        }
        if index != 0 {
            continue;
        }
        let mut depth2: Vec<String> = Vec::new();
        for first in &depth1 {
            for kind in TRANSFORMS {
                // HTML/JSON escapes of an already-escaped spelling (24x per
                // value byte) are periodic needles that make the automaton
                // build pathological and are not mainstream spellings; they
                // are only composed onto inputs up to one frame long.
                if first.len() > 256
                    && matches!(
                        kind,
                        Transform::HtmlHex
                            | Transform::HtmlDecimal
                            | Transform::JsonEscapesUpper
                            | Transform::JsonEscapesLower
                    )
                {
                    continue;
                }
                if let Some(second) = apply_transform(kind, first) {
                    if second.len() <= MAX_VARIANT_LEN {
                        depth2.push(second);
                    }
                }
            }
        }
        let bytes = base.len()
            + depth1.iter().map(String::len).sum::<usize>()
            + depth2.iter().map(String::len).sum::<usize>();
        if bytes <= MAX_VARIANT_BYTES_PER_VALUE {
            for variant in depth2 {
                push(variant);
            }
        } else {
            // Fail closed: the raw and depth-1 spellings are registered, but
            // not every composed spelling is, so live streams must mask the
            // whole message while this value is registered.
            oversized.set(true);
            tracing::warn!(
                bytes,
                "known-secret variant closure exceeds its byte budget; streams fail closed"
            );
        }
    }
    if let Ok(quoted) = serde_json::to_string(value) {
        if quoted.len() >= 2 {
            let escaped = &quoted[1..quoted.len() - 1];
            push(escaped.to_string());
            if escaped.contains("\\u") {
                push(uppercase_unicode_escapes(escaped));
            }
        }
    }
    // The condense step drops whitespace and invisibles, so a value whose own
    // text contains them still matches its plain spelling.
    let condensed: Vec<String> = variants
        .iter()
        .map(|variant| variant.chars().filter(|c| !is_scrub_noise(*c)).collect())
        .filter(|condensed: &String| condensed.len() >= MIN_KNOWN_SECRET_LEN)
        .collect();
    for variant in condensed {
        variants.insert(variant);
    }
    (variants, oversized.get())
}

/// One transform of the variant composition closure (R9).
#[derive(Clone, Copy)]
pub(super) enum Transform {
    Base64Std,
    Base64StdNoPad,
    Base64Url,
    Base64UrlNoPad,
    Base32,
    Base32NoPad,
    Base32Lower,
    Base32NoPadLower,
    HexLower,
    HexUpper,
    HexColonLower,
    HexColonUpper,
    HexDashLower,
    HexDashUpper,
    HexSpaceLower,
    HexSpaceUpper,
    HexEscapedLower,
    HexEscapedUpper,
    HexZeroXLower,
    HexZeroXUpper,
    PercentUpper,
    PercentLower,
    PercentMinimalUpper,
    PercentMinimalLower,
    PercentAllUpper,
    JsonEscapesUpper,
    JsonEscapesLower,
    HtmlHex,
    HtmlDecimal,
    Nfkc,
}

/// The transform set the closure composes (order defines the depth-2 order,
/// so the mainstream pairs are generated first).
pub(super) const TRANSFORMS: [Transform; 30] = [
    Transform::Base64Std,
    Transform::Base64StdNoPad,
    Transform::Base64Url,
    Transform::Base64UrlNoPad,
    Transform::HexLower,
    Transform::HexUpper,
    Transform::HexColonLower,
    Transform::HexColonUpper,
    Transform::HexDashLower,
    Transform::HexDashUpper,
    Transform::HexSpaceLower,
    Transform::HexSpaceUpper,
    Transform::PercentUpper,
    Transform::PercentLower,
    Transform::PercentMinimalUpper,
    Transform::PercentMinimalLower,
    Transform::PercentAllUpper,
    Transform::Base32,
    Transform::Base32NoPad,
    Transform::Base32Lower,
    Transform::Base32NoPadLower,
    Transform::HexEscapedLower,
    Transform::HexEscapedUpper,
    Transform::HexZeroXLower,
    Transform::HexZeroXUpper,
    Transform::JsonEscapesUpper,
    Transform::JsonEscapesLower,
    Transform::HtmlHex,
    Transform::HtmlDecimal,
    Transform::Nfkc,
];

/// Budget for one value's depth-2 closure, counted in **bytes** so a 256-byte
/// secret's full closure fits. A closure over budget is dropped whole (depth 1
/// remains) and the value is flagged [`registry_oversized`], which makes live
/// streams fail closed rather than silently miss spellings (R10).
const MAX_VARIANT_BYTES_PER_VALUE: usize = 2 * 1024 * 1024;

/// Longest needle registered: every registered value's raw form must be a
/// needle, so this matches the registration cap. Longer composed spellings
/// are left to the decoded scan.
pub(super) const MAX_VARIANT_LEN: usize = MAX_KNOWN_SECRET_LEN;

/// Apply one transform; `None` when it is the identity (or too short to be a
/// useful needle).
pub(super) fn apply_transform(kind: Transform, value: &str) -> Option<String> {
    let transformed = match kind {
        Transform::Base64Std => STANDARD.encode(value),
        Transform::Base64StdNoPad => STANDARD_NO_PAD.encode(value),
        Transform::Base64Url => URL_SAFE.encode(value),
        Transform::Base64UrlNoPad => URL_SAFE_NO_PAD.encode(value),
        Transform::Base32 => base32_encode(value.as_bytes(), true, false),
        Transform::Base32NoPad => base32_encode(value.as_bytes(), false, false),
        Transform::Base32Lower => base32_encode(value.as_bytes(), true, true),
        Transform::Base32NoPadLower => base32_encode(value.as_bytes(), false, true),
        Transform::HexLower => hex_encode(value, false),
        Transform::HexUpper => hex_encode(value, true),
        Transform::HexColonLower => hex_separated(value, ":", false),
        Transform::HexColonUpper => hex_separated(value, ":", true),
        Transform::HexDashLower => hex_separated(value, "-", false),
        Transform::HexDashUpper => hex_separated(value, "-", true),
        Transform::HexSpaceLower => hex_separated(value, " ", false),
        Transform::HexSpaceUpper => hex_separated(value, " ", true),
        Transform::HexEscapedLower => escaped_hex(value, "\\x", false),
        Transform::HexEscapedUpper => escaped_hex(value, "\\X", true),
        Transform::HexZeroXLower => hex_zero_x(value, false),
        Transform::HexZeroXUpper => hex_zero_x(value, true),
        Transform::PercentUpper => percent_encode(value, true),
        Transform::PercentLower => percent_encode(value, false),
        Transform::PercentMinimalUpper => percent_encode_minimal(value, true),
        Transform::PercentMinimalLower => percent_encode_minimal(value, false),
        Transform::PercentAllUpper => percent_encode_all(value),
        Transform::JsonEscapesUpper => unicode_escaped(value, "\\u", true),
        Transform::JsonEscapesLower => unicode_escaped(value, "\\u", false),
        Transform::HtmlHex => html_entities(value, true),
        Transform::HtmlDecimal => html_entities(value, false),
        Transform::Nfkc => value.nfkc().collect(),
    };
    if transformed == value || transformed.len() < MIN_KNOWN_SECRET_LEN {
        None
    } else {
        Some(transformed)
    }
}
