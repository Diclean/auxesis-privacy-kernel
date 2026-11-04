//! Token minting: the [`Anonymizer`] type and its masking pass.

use std::collections::{HashMap, HashSet};
use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::normalize::NormalizedText;
use crate::recognizer::{masked_regions, span_is_well_formed, split_long_spans};
use crate::span::{EntityKind, Span};

use super::escape::push_escaped;
use super::normalize::normalize_value;
use super::placeholder::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
use super::token_map::TokenMap;

type HmacSha256 = Hmac<Sha256>;

/// Maps spans to stable tokens using a per-session key.
pub struct Anonymizer {
    key: [u8; 32],
    table: HashMap<[u8; 32], String>,
    used_tokens: HashSet<String>,
}

impl Anonymizer {
    /// Build an anonymizer for one session with a 32-byte key from the vault.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            table: HashMap::new(),
            used_tokens: HashSet::new(),
        }
    }

    /// Replace every span in `text` with its delimited placeholder.
    ///
    /// Overlapping or adjacent spans of every kind are merged into one masked
    /// region first with `crate::recognizer::masked_regions`, so no byte of any
    /// detection can survive in the clear and the masked text is exactly the
    /// union of the detected spans. Every region longer than
    /// [`crate::recognizer::MAX_SPAN_BYTES`] is split first, so one token never
    /// covers an unbounded region. Each placeholder is written as
    /// `⟦KIND_<fingerprint>⟧`; the text between placeholders is escaped so only
    /// our delimiters survive raw (see the module docs). Returns the masked
    /// text and the map of tokens; the map stores every occurrence's exact
    /// surface form, so [`Anonymizer::restore`] is exact even when one token
    /// covers several spellings of the same value.
    pub fn anonymize(&mut self, text: &str, spans: &[Span]) -> (String, TokenMap) {
        let well_formed: Vec<Span> = spans
            .iter()
            .copied()
            .filter(|span| span_is_well_formed(text, span))
            .collect();
        let ordered = split_long_spans(text, masked_regions(well_formed));

        let mut masked = String::with_capacity(text.len());
        let mut pairs = TokenMap::default();
        let mut cursor = 0usize;
        for span in ordered {
            if span.start < cursor {
                continue;
            }
            push_escaped(&mut masked, &text[cursor..span.start]);
            let surface = &text[span.start..span.end];
            let (token, is_new) = self.token_for(span.kind, surface);
            pairs.push_occurrence(token.clone(), surface.to_string());
            if is_new {
                pairs.push_entry(token.clone(), surface.to_string());
            }
            masked.push(PLACEHOLDER_OPEN);
            masked.push_str(&token);
            masked.push(PLACEHOLDER_CLOSE);
            cursor = span.end;
        }
        push_escaped(&mut masked, &text[cursor..]);
        (masked, pairs)
    }
}

impl Anonymizer {
    /// The token for one value, assigning a new one on first sight.
    pub fn token_for(&mut self, kind: EntityKind, value: &str) -> (String, bool) {
        let digest = self.digest(kind, value);
        if let Some(existing) = self.table.get(&digest) {
            return (existing.clone(), false);
        }
        let token = self.make_token(kind, &digest);
        self.table.insert(digest, token.clone());
        self.used_tokens.insert(token.clone());
        (token, true)
    }

    /// The number of distinct values seen this session.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Whether no value has been seen yet.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// A keyed token: the kind plus the hex of `digest`, disambiguated if two
    /// values ever share the same short prefix. The used-token set makes the
    /// collision check O(1) instead of a scan of the table.
    fn make_token(&self, kind: EntityKind, digest: &[u8; 32]) -> String {
        let mut base = String::with_capacity(kind.as_str().len() + 13);
        base.push_str(kind.as_str());
        base.push('_');
        for byte in &digest[..6] {
            base.push_str(&format!("{byte:02X}"));
        }
        let mut attempt = 0u32;
        loop {
            let token = if attempt == 0 {
                base.clone()
            } else {
                format!("{base}_{attempt}")
            };
            if !self.used_tokens.contains(&token) {
                return token;
            }
            attempt += 1;
        }
    }

    pub(super) fn digest(&self, kind: EntityKind, value: &str) -> [u8; 32] {
        let normalized = normalize_value(kind, value);
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts a key of any length");
        mac.update(kind.as_str().as_bytes());
        mac.update(b"\x1f");
        mac.update(normalized.as_bytes());
        // A spelling the scan folds (`𝐄𝐒91…`, `ЕS91…`, a hidden or
        // Unicode space) keys on its own bytes too, so it gets its own token and
        // restores to itself, never to another spelling of the value. A value
        // with nothing to fold (all ASCII text) keeps its key.
        if !NormalizedText::folded_views(value).is_empty() {
            mac.update(b"\x1e");
            mac.update(value.as_bytes());
        }
        let tag = mac.finalize().into_bytes();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&tag);
        digest
    }
}

impl fmt::Debug for Anonymizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Anonymizer")
            .field("key", &"<redacted>")
            .field("entries", &self.table.len())
            .finish()
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    #[test]
    fn old_version_vector_pseudonym() {
        let mut anonymizer = Anonymizer::new([7; 32]);
        let digest = anonymizer.digest(EntityKind::Email, "fixture@example.test");
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "b4d6bc78e97f48c133166b953c826b835541bce898acc98515c95043be766f60"
        );
        assert_eq!(
            anonymizer
                .token_for(EntityKind::Email, "fixture@example.test")
                .0,
            "EMAIL_B4D6BC78E97F"
        );
        let digest = anonymizer.digest(EntityKind::Person, "Groß");
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "8589ba4780bcbac0292d388cd34c00507eacd37bd015820919a3c783e48ca82c"
        );
    }
}
