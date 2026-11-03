//! Session-token detection: which `⟦KIND_…⟧` strings this session issued, and
//! the blanked and stripped views the gate detects on.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};

use crate::anonymize::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
use crate::span::EntityKind;

/// A standalone token marker issued by this session.
pub(super) struct TokenRange {
    pub(super) start: usize,
    pub(super) end: usize,
}

/// Every standalone, well-formed known token marker in `text` that this session
/// issued. All foreign, nested, entity-encoded, or unresolved marker text stays
/// ordinary detector input.
pub(super) fn token_ranges(text: &str, minted: &BTreeSet<String>) -> Vec<TokenRange> {
    if minted.is_empty() {
        return Vec::new();
    }
    let issued: HashSet<&str> = minted.iter().map(String::as_str).collect();
    let (mut candidates, mut at) = (Vec::new(), 0);
    while let Some(offset) = text[at..].find(PLACEHOLDER_OPEN) {
        let start = at + offset;
        match session_token_len(&text[start..]) {
            Some(len) => {
                let (open, close) = (PLACEHOLDER_OPEN.len_utf8(), PLACEHOLDER_CLOSE.len_utf8());
                let end = start + len;
                let body = &text[start + open..start + len - close];
                if issued.contains(body) {
                    candidates.push(TokenRange { start, end });
                }
                at = end;
            }
            None => {
                at = start + PLACEHOLDER_OPEN.len_utf8();
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    // Walk the decoded marker spans and candidates together. The old code
    // searched all spans for exact, enclosing and unresolved matches per token
    // (`contains`/`any`), which made repeated issued tokens quadratic.
    let decoded = crate::decode::DecodedText::new(text);
    let markers = decoded.markers();
    let unresolved = decoded.unresolved();
    let mut found = Vec::with_capacity(candidates.len());
    let (mut marker_at, mut unresolved_at, mut outer_end) = (0, 0, 0);
    for candidate in candidates {
        while marker_at < markers.len() && markers[marker_at].0 < candidate.start {
            outer_end = outer_end.max(markers[marker_at].1);
            marker_at += 1;
        }
        let nested = outer_end >= candidate.end;

        let mut group_end = marker_at;
        let mut exact = false;
        let mut group_end_max = outer_end;
        while group_end < markers.len() && markers[group_end].0 == candidate.start {
            let (_, end) = markers[group_end];
            exact |= end == candidate.end;
            group_end_max = group_end_max.max(end);
            group_end += 1;
        }
        if group_end > marker_at {
            // These spans are prior context for the next candidate, but their
            // shared start cannot make this candidate nested in itself.
            marker_at = group_end;
            outer_end = group_end_max;
        }

        while unresolved_at < unresolved.len() && unresolved[unresolved_at].1 <= candidate.start {
            unresolved_at += 1;
        }
        let overlaps_unresolved = unresolved
            .get(unresolved_at)
            .is_some_and(|&(from, _)| from < candidate.end);
        if exact && !nested && !overlaps_unresolved {
            found.push(candidate);
        }
    }
    found
}

/// `text` with every issued token replaced by blanks of the same byte length;
/// with no token it is borrowed, since the clear text already is the view.
pub(super) fn blank_minted<'a>(text: &'a str, tokens: &[TokenRange]) -> Cow<'a, str> {
    if tokens.is_empty() {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    for token in tokens {
        let close = token.end - PLACEHOLDER_CLOSE.len_utf8();
        let blank = token.start;
        out.push_str(&text[from..blank]);
        out.extend(std::iter::repeat_n(' ', close - blank));
        out.extend(std::iter::repeat_n(' ', token.end - close));
        from = token.end;
    }
    out.push_str(&text[from..]);
    Cow::Owned(out)
}

/// The kept stretches of a stripped text: `(offset in the view, offset in the
/// original, length)`.
pub(super) struct Segments(Vec<(usize, usize, usize)>);

impl Segments {
    /// The original offset of view offset `at`; `ending` reads it as the end of
    /// a span, so a span that stops where a token was ends before the token.
    pub(super) fn original(&self, at: usize, ending: bool) -> Option<usize> {
        // Stretches are sorted by view offset: a binary search, not a scan.
        let index = self.0.partition_point(|&(view, _, len)| {
            if ending {
                view + len < at
            } else {
                view + len <= at
            }
        });
        let &(view, original, len) = self.0.get(index)?;
        let inside = if ending {
            view < at && at <= view + len
        } else {
            view <= at && at < view + len
        };
        inside.then(|| original + (at - view))
    }
}

/// `text` with every token deleted, and how to map its offsets back.
pub(super) fn strip_tokens(text: &str, tokens: &[TokenRange]) -> (String, Segments) {
    let (mut out, mut segments, mut from) = (String::with_capacity(text.len()), Vec::new(), 0);
    let ends = tokens
        .iter()
        .map(|t| (t.start, t.end))
        .chain(std::iter::once((text.len(), text.len())));
    for (start, end) in ends {
        if start > from {
            segments.push((out.len(), from, start - from));
            out.push_str(&text[from..start]);
        }
        from = end;
    }
    (out, Segments(segments))
}

/// Longest token body (the bytes between `⟦` and `⟧`) read as a session token.
/// A real one is a kind, `_`, 12 hex digits and an optional `_N`, far below this.
pub(super) const MAX_SESSION_TOKEN_BYTES: usize = 64;

/// Byte length of the session token that starts `text` (`⟦`, a known kernel
/// kind, `_`, 12 uppercase hex digits, an optional `_<n>`, `⟧`), or `None`.
pub(super) fn session_token_len(text: &str) -> Option<usize> {
    let body = text.strip_prefix(PLACEHOLDER_OPEN)?;
    // Look for the closer only within the longest token: text of a million
    // openers and no closer must not rescan the rest at each opener.
    let mut window = body
        .len()
        .min(MAX_SESSION_TOKEN_BYTES + PLACEHOLDER_CLOSE.len_utf8());
    while !body.is_char_boundary(window) {
        window -= 1;
    }
    let close = body[..window].find(PLACEHOLDER_CLOSE)?;
    let body = &body[..close];
    let is_hex = |s: &str| {
        s.len() == 12
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    };
    let kind = EntityKind::ALL.into_iter().find(|kind| {
        body.strip_prefix(kind.as_str())
            .is_some_and(|rest| rest.starts_with('_'))
    })?;
    let fingerprint = body.strip_prefix(kind.as_str())?.strip_prefix('_')?;
    let valid = if let Some((hex, number)) = fingerprint.rsplit_once('_') {
        is_hex(hex) && (1..=3).contains(&number.len()) && number.bytes().all(|b| b.is_ascii_digit())
    } else {
        is_hex(fingerprint)
    };
    valid.then(|| PLACEHOLDER_OPEN.len_utf8() + close + PLACEHOLDER_CLOSE.len_utf8())
}
