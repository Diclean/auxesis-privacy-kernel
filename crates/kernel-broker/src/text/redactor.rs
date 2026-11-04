//! The single-pass tokenizer behind `redact_secrets`: PEM blocks, URL
//! userinfo, header values, name/value pairs and vendor-prefixed tokens.

use super::shapes::{
    is_percent_scheme_separator, is_scheme, is_value_delim, looks_like_secret, value_is_secret,
};
use super::*;

/// The one-pass redactor: a cursor walks the text, each construct consumes
/// the bytes it decides on, and no text is ever rescanned for a failed
/// candidate.
pub(super) struct Redactor<'a> {
    pub(super) text: &'a str,
    pub(super) bytes: &'a [u8],
    pub(super) out: String,
    /// `text[..copied]` is already in `out`.
    pub(super) copied: usize,
    pub(super) cursor: usize,
}

impl Redactor<'_> {
    pub(super) fn run(mut self) -> String {
        while self.cursor < self.bytes.len() {
            let byte = self.bytes[self.cursor];
            if byte == b'-' && self.try_pem() {
                continue;
            }
            if byte == b'-' && self.try_dash_flag() {
                continue;
            }
            if (byte == b'"' || byte == b'\'') && self.try_quoted_name() {
                continue;
            }
            // A run always starts here: `try_run` consumes the whole run and
            // every masking path lands after a value delimiter.
            if is_run_byte(byte) {
                self.try_run();
                continue;
            }
            self.copy_char();
        }
        self.out.push_str(&self.text[self.copied..]);
        self.out
    }

    fn copy_char(&mut self) {
        let len = self.text[self.cursor..]
            .chars()
            .next()
            .map_or(1, char::len_utf8);
        self.cursor += len;
    }

    fn flush_to(&mut self, end: usize) {
        if end > self.copied {
            self.out.push_str(&self.text[self.copied..end]);
        }
        self.copied = self.copied.max(end);
    }

    /// Replace the bytes `[body_start, consumed_end)` with the mask, keeping
    /// an optional closing quote after the mask. `consumed_end` is the end of
    /// the value (quote included) and becomes the new cursor.
    fn mask_value(
        &mut self,
        body_start: usize,
        body_end: usize,
        consumed_end: usize,
        closed: bool,
    ) {
        self.flush_to(body_start);
        self.out.push_str(MASK);
        if closed {
            self.out.push_str(&self.text[body_end..body_end + 1]);
        }
        self.copied = consumed_end;
        self.cursor = consumed_end;
    }

    /// `-----BEGIN <label>-----` blocks whose label names a private key,
    /// through the matching `-----END <label>-----` (case-insensitive label).
    fn try_pem(&mut self) -> bool {
        const BEGIN: &[u8] = b"-----BEGIN ";
        if !self.bytes[self.cursor..].starts_with(BEGIN) {
            return false;
        }
        let label_start = self.cursor + BEGIN.len();
        let limit = (label_start + 128).min(self.bytes.len());
        let Some(offset) = find_bytes(&self.bytes[label_start..limit], b"-----") else {
            return false;
        };
        let label_end = label_start + offset;
        let marker_end = label_end + b"-----".len();
        let label = &self.text[label_start..label_end];
        if !label.to_ascii_lowercase().contains("private key") {
            return false;
        }
        self.flush_to(self.cursor);
        self.out.push_str(&self.text[self.cursor..marker_end]);
        self.out.push_str(MASK);
        let end_marker = format!("-----END {label}-----");
        match self.text[marker_end..].find(&end_marker) {
            Some(offset) => {
                self.out.push_str(&end_marker);
                let end = marker_end + offset + end_marker.len();
                self.copied = end;
                self.cursor = end;
            }
            // No end marker: everything that follows may be key material.
            None => {
                self.copied = self.bytes.len();
                self.cursor = self.bytes.len();
            }
        }
        true
    }

    /// `curl -u user:pass`, `--user user:pass`, `--password pass`: redact the
    /// next value when it carries a credential shape.
    fn try_dash_flag(&mut self) -> bool {
        const FLAGS: &[&str] = &["--password", "--user", "-u"];
        let mut matched = None;
        for flag in FLAGS {
            if !self.text[self.cursor..].starts_with(flag) {
                continue;
            }
            let after = self.cursor + flag.len();
            // Never read a short flag out of a longer one (`-utf8`, `x-u`).
            if self.cursor > 0
                && (self.bytes[self.cursor - 1] == b'-' || is_run_byte(self.bytes[self.cursor - 1]))
            {
                continue;
            }
            let boundary_ok = match self.bytes.get(after) {
                Some(byte) if byte.is_ascii_whitespace() => true,
                Some(b'=') => true,
                None => true,
                _ => false,
            };
            if !boundary_ok {
                continue;
            }
            matched = Some(flag.len());
            break;
        }
        let Some(flag_len) = matched else {
            return false;
        };
        let mut p = self.cursor + flag_len;
        if self.bytes.get(p) == Some(&b'=') {
            p += 1;
        }
        while p < self.bytes.len() && matches!(self.bytes[p], b' ' | b'\t') {
            p += 1;
        }
        // `curl --user=(admin:pass)` — the bracket wrapper is skipped
        // inside the same bounded window as any pair; `<>` is masked whole,
        // `(…)` keeps its parentheses around the mask.
        if let Some((body_start, body_end)) = self.bracket_body(p) {
            let inner = &self.text[body_start..body_end];
            let value = inner.trim();
            if !(value.contains(':') || looks_like_secret(value)) {
                return false;
            }
            if self.bytes[p] == b'<' {
                self.mask_value(p, body_end + 1, body_end + 1, false);
                return true;
            }
            let value_start = body_start + (inner.len() - inner.trim_start().len());
            let value_end = value_start + value.len();
            self.mask_value(value_start, value_end, value_end, false);
            return true;
        }
        let rest = &self.text[p..];
        let end = rest
            .find(|c: char| c.is_whitespace() || is_value_delim(c))
            .unwrap_or(rest.len());
        let value = &self.text[p..p + end];
        if !(value.contains(':') || looks_like_secret(value)) {
            return false;
        }
        self.flush_to(p);
        self.out.push_str(MASK);
        self.copied = p + end;
        self.cursor = self.copied;
        true
    }

    /// One token/name run, consumed in one decision.
    fn try_run(&mut self) {
        let start = self.cursor;
        let mut end = start;
        while end < self.bytes.len() && is_run_byte(self.bytes[end]) {
            end += 1;
        }
        let run = &self.text[start..end];
        // PuTTY/OpenSSH new-format private keys carry no BEGIN marker; the
        // key body follows the header, so everything after it is treated as
        // key material.
        const PUTTY: &[u8] = b"PuTTY-User-Key-File-";
        if run.len() >= PUTTY.len() && run.as_bytes()[..PUTTY.len()].eq_ignore_ascii_case(PUTTY) {
            self.flush_to(start);
            self.out.push_str(&run[..PUTTY.len()]);
            self.out.push_str(MASK);
            self.copied = self.bytes.len();
            self.cursor = self.bytes.len();
            return;
        }
        if let Some(prefix_len) = vendor_prefix(run) {
            if run.len() > 10 {
                self.flush_to(start);
                self.out.push_str(&run[..prefix_len]);
                self.out.push_str(MASK);
                self.copied = end;
                self.cursor = end;
                return;
            }
        }
        if run.as_bytes().starts_with(b"AKIA") {
            let extra = run.as_bytes()[4..]
                .iter()
                .take_while(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                .count();
            if extra >= 16 {
                self.flush_to(start + 4);
                self.out.push_str(MASK);
                self.copied = start + 4 + extra;
                self.cursor = self.copied;
                return;
            }
        }
        if run.len() >= 20
            && run.as_bytes()[..3].eq_ignore_ascii_case(b"eyJ")
            && run.bytes().filter(|byte| *byte == b'.').count() >= 2
        {
            self.flush_to(start + 3);
            self.out.push_str(MASK);
            self.copied = end;
            self.cursor = end;
            return;
        }
        if is_scheme(run) && self.text[end..].starts_with("://") {
            if !self.try_url_userinfo(start, end + "://".len()) {
                self.cursor = end;
            }
            return;
        }
        // A percent-encoded DSN (`postgres%3A%2F%2Fu:pass@host`).
        if is_scheme(run) && is_percent_scheme_separator(self.bytes, end) {
            if !self.try_url_userinfo(start, end + 9) {
                self.cursor = end;
            }
            return;
        }
        if !self.try_name(run, end) {
            self.cursor = end;
        }
    }

    /// Replace the userinfo of `scheme://user[:pass]@` (or its
    /// percent-encoded spelling) with the mask; `auth_start` is the first
    /// authority byte, after the scheme separator.
    fn try_url_userinfo(&mut self, start: usize, auth_start: usize) -> bool {
        let mut at = None;
        let mut k = auth_start;
        while k < self.bytes.len() {
            let byte = self.bytes[k];
            if byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>' | b'`' | b'\\'
                )
            {
                break;
            }
            if byte == b'@' {
                at = Some(k);
            }
            k += 1;
        }
        let Some(at) = at else {
            return false;
        };
        self.flush_to(start);
        self.out.push_str(&self.text[start..auth_start]);
        self.out.push_str(MASK);
        self.out.push('@');
        self.copied = at + 1;
        self.cursor = at + 1;
        true
    }

    /// A quoted key (`"api_key"`, `'token'`): unwrap and share the pair rule.
    /// An escaped closing quote (`\"api_key\":…`, a JSON fragment copied out
    /// of an encoded string) closes the name too. Padding
    /// spaces inside the quotes (`" api_key "`) are skipped before and after
    /// the run, so a padded key is still a key.
    fn try_quoted_name(&mut self) -> bool {
        let quote = self.bytes[self.cursor];
        let mut name_start = self.cursor + 1;
        while matches!(self.bytes.get(name_start), Some(b' ' | b'\t')) {
            name_start += 1;
        }
        let mut name_end = name_start;
        while name_end < self.bytes.len() && is_run_byte(self.bytes[name_end]) {
            name_end += 1;
        }
        if name_end == name_start {
            return false;
        }
        let after_padding = {
            let mut p = name_end;
            while matches!(self.bytes.get(p), Some(b' ' | b'\t')) {
                p += 1;
            }
            p
        };
        let after_name = if self.bytes.get(after_padding) == Some(&quote) {
            after_padding + 1
        } else if self.bytes.get(name_end) == Some(&b'\\')
            && self.bytes.get(name_end + 1) == Some(&quote)
        {
            name_end + 2
        } else {
            return false;
        };
        let name = &self.text[name_start..name_end];
        let gate = header_gate(name);
        let info = classify_name(name);
        if gate.is_none() && info.strength == Strength::None {
            return false;
        }
        self.try_pair(after_name, info, gate)
    }

    /// `Bearer`/`Basic` keyword handling before the name rules.
    fn try_name(&mut self, name: &str, name_end: usize) -> bool {
        if (name.eq_ignore_ascii_case("bearer") || name.eq_ignore_ascii_case("basic"))
            && self.try_scheme_value(name_end)
        {
            return true;
        }
        let gate = header_gate(name);
        let info = classify_name(name);
        if gate.is_none() && info.strength == Strength::None {
            return false;
        }
        self.try_pair(name_end, info, gate)
    }

    /// The body span of a `(…)`/`<…>` wrapper at `p`, bounded by
    /// [`PAIR_SKIP_LIMIT`]; `None` when there is no wrapper or it does not
    /// close inside the window.
    fn bracket_body(&self, p: usize) -> Option<(usize, usize)> {
        let close = match self.bytes.get(p) {
            Some(b'(') => b')',
            Some(b'<') => b'>',
            _ => return None,
        };
        let body_start = p + 1;
        let limit = (body_start + PAIR_SKIP_LIMIT).min(self.bytes.len());
        let mut end = body_start;
        while end < limit && self.bytes[end] != close {
            end += 1;
        }
        if end >= limit || end == body_start {
            return None;
        }
        Some((body_start, end))
    }

    /// Redact a `Bearer <value>` / `Basic <value>` value that looks like an
    /// opaque secret.
    ///
    /// The whitespace between scheme and value is skipped with the
    /// same bounded rule as every other pair, so an obs-folded credential
    /// (`Authorization: Bearer\r\n  eyJ…`, what every header wrapper emits)
    /// is one value and not an invisible tail. A bracketed value
    /// (`Bearer (…)`) is handled like every other pair's bracket wrapper.
    fn try_scheme_value(&mut self, name_end: usize) -> bool {
        let p = self.skip_pair_whitespace(name_end, PAIR_SKIP_LIMIT);
        if p == name_end {
            return false;
        }
        if let Some((body_start, body_end)) = self.bracket_body(p) {
            let inner = &self.text[body_start..body_end];
            let value = inner.trim();
            if !looks_like_secret(value) {
                return false;
            }
            if self.bytes[p] == b'<' {
                self.mask_value(p, body_end + 1, body_end + 1, false);
                return true;
            }
            let value_start = body_start + (inner.len() - inner.trim_start().len());
            let value_end = value_start + value.len();
            self.mask_value(value_start, value_end, value_end, false);
            return true;
        }
        let quote = self
            .bytes
            .get(p)
            .copied()
            .filter(|byte| *byte == b'"' || *byte == b'\'');
        let body_start = p + usize::from(quote.is_some());
        let (body_end, closed) = self.scan_value(body_start, quote, true);
        let value = &self.text[body_start..body_end];
        if !looks_like_secret(value) {
            return false;
        }
        self.mask_value(body_start, body_end, body_end + usize::from(closed), closed);
        true
    }

    /// A `name<separator>value` pair (also used by quoted keys).
    ///
    /// The separator and the value may be split across lines (pretty-printed
    /// JSON fragments, YAML, a shell line continuation); the skip window is
    /// bounded so an adversarial text stays linear.
    fn try_pair(&mut self, name_end: usize, info: NameInfo, gate: Option<HeaderGate>) -> bool {
        // A bracketed query suffix (`?auth[token]=`, `?token[]=`) sits
        // between the name run and the separator.
        let p = self.skip_pair_whitespace(name_end, PAIR_SKIP_LIMIT);
        let p = self.skip_pair_whitespace(self.skip_name_bracket_suffix(p), PAIR_SKIP_LIMIT);
        let Some(separator_len) = self.separator_at(p) else {
            return false;
        };
        let is_colon = self.bytes[p] == b':';
        let mut q = self.skip_pair_whitespace(p + separator_len, PAIR_SKIP_LIMIT);
        // A repeated separator (`api_key = = …`, `key%3D%3D…`) names
        // the same pair; consume at most two extras, inside the same bounded
        // windows.
        for _ in 0..2 {
            let Some(extra) = self.separator_at(q) else {
                break;
            };
            q = self.skip_pair_whitespace(q + extra, PAIR_SKIP_LIMIT);
        }
        if let Some(gate) = gate.filter(|_| is_colon) {
            return self.try_header_value(q, gate);
        }
        // A value wrapped by the punctuation the same sentence uses
        // — `password=(mysecretpassphrase)`, `api_key=<…>` — is still the
        // value of the pair; the wrapper is skipped inside the same bounded
        // window, never by rescanning.
        if self.try_bracketed_value(q, info) {
            return true;
        }
        // `\"value\"`: the quote of an encoded JSON fragment.
        if self.bytes.get(q) == Some(&b'\\')
            && matches!(self.bytes.get(q + 1), Some(b'"') | Some(b'\''))
        {
            q += 1;
        }
        let quote = self
            .bytes
            .get(q)
            .copied()
            .filter(|byte| *byte == b'"' || *byte == b'\'');
        let body_start = q + usize::from(quote.is_some());
        let (body_end, closed) = self.scan_value(body_start, quote, false);
        let value = &self.text[body_start..body_end];
        if !value_is_secret(info, value, quote.is_some()) {
            return false;
        }
        self.mask_value(body_start, body_end, body_end + usize::from(closed), closed);
        true
    }

    /// Skip a bracketed suffix on a name (`auth[token]=`,
    /// `token[]=`), inside a constant window.
    fn skip_name_bracket_suffix(&self, p: usize) -> usize {
        if self.bytes.get(p) != Some(&b'[') {
            return p;
        }
        let limit = (p + 64).min(self.bytes.len());
        let mut q = p + 1;
        while q < limit && self.bytes[q] != b']' {
            q += 1;
        }
        if q < limit {
            q + 1
        } else {
            p
        }
    }

    /// Redact a value wrapped in `(…)` or `<…>`.
    ///
    /// `(`/`)`/`<`/`>` are value delimiters, so without this the
    /// value after the separator reads as empty and the pair disappears;
    /// `password=(mysecretpassphrase)` — prose, maths, a shell transcript —
    /// leaked verbatim. The scan for the closing bracket is bounded
    /// ([`PAIR_SKIP_LIMIT`]), so this stays linear. Parentheses are kept
    /// around the mask (`api_key=(<redacted>)`); an angle-bracket wrapper is
    /// replaced whole, because `<<redacted>>` is not the `<redacted>` idiom
    /// the rest of the system uses.
    fn try_bracketed_value(&mut self, q: usize, info: NameInfo) -> bool {
        let Some((body_start, end)) = self.bracket_body(q) else {
            return false;
        };
        let inner = &self.text[body_start..end];
        let value = inner.trim();
        if !value_is_secret(info, value, false) {
            return false;
        }
        if self.bytes[q] == b'<' {
            // Mask the wrapper as well: `api_key=<redacted>`.
            self.mask_value(q, end + 1, end + 1, false);
            return true;
        }
        let value_start = body_start + (inner.len() - inner.trim_start().len());
        let value_end = value_start + value.len();
        self.mask_value(value_start, value_end, value_end, false);
        true
    }

    /// Skip the whitespace — including line breaks, indentation, a single
    /// shell line continuation, percent-encoded spaces
    /// (`api_key%20=%20…`) and JSON5 comments — between a
    /// name/separator and the value, up to `limit` bytes.
    fn skip_pair_whitespace(&self, mut p: usize, limit: usize) -> usize {
        let end = (p + limit).min(self.bytes.len());
        while p < end {
            match self.bytes[p] {
                b' ' | b'\t' | b'\r' | b'\n' => p += 1,
                b'\\' if matches!(self.bytes.get(p + 1), Some(b'\r' | b'\n')) => p += 1,
                b'%' if self.bytes.get(p + 1) == Some(&b'2')
                    && matches!(self.bytes.get(p + 2), Some(b'0' | b'9')) =>
                {
                    p += 3;
                }
                b'/' if self.bytes.get(p + 1) == Some(&b'*') => {
                    // `/* … */`: skip the comment whole or stop.
                    let mut q = p + 2;
                    let mut closed = false;
                    while q + 1 < end {
                        if self.bytes[q] == b'*' && self.bytes[q + 1] == b'/' {
                            closed = true;
                            break;
                        }
                        q += 1;
                    }
                    if !closed {
                        break;
                    }
                    p = q + 2;
                }
                b'/' if self.bytes.get(p + 1) == Some(&b'/')
                    && p > 0
                    && matches!(self.bytes[p - 1], b' ' | b'\t')
                    && matches!(self.bytes.get(p + 2), Some(b' ' | b'\t')) =>
                {
                    // `// …`: skip to the end of the line. Requiring a space
                    // after `//` keeps a value that starts with `//` (a
                    // protocol-relative URL) from being eaten.
                    let mut q = p + 2;
                    while q < end && self.bytes[q] != b'\n' {
                        q += 1;
                    }
                    p = q;
                }
                _ => break,
            }
        }
        // A `//` comment can end on the window edge, a byte count: round up to
        // a character boundary so callers can slice at `p`.
        while p < self.bytes.len() && !self.text.is_char_boundary(p) {
            p += 1;
        }
        p
    }

    /// Redact a header line's value (to the end of the line, quotes and all).
    ///
    /// The gate looks at a bounded window so an adversarial same-line run of
    /// headers stays linear; a value that passes the gate is redacted through
    /// the whole line (redacting more than was inspected is safe).
    fn try_header_value(&mut self, q: usize, gate: HeaderGate) -> bool {
        const SCAN_LIMIT: usize = 1024;
        let rest = &self.text[q..];
        let line_end = rest.find(['\r', '\n']).unwrap_or(rest.len());
        // The window is a byte count: round it down to a character boundary.
        let mut scan_end = line_end.min(SCAN_LIMIT);
        while !rest.is_char_boundary(scan_end) {
            scan_end -= 1;
        }
        let segment = &rest[..scan_end];
        let value = segment.trim();
        if value.is_empty() {
            return false;
        }
        let redact = match gate {
            HeaderGate::Shaped => looks_like_secret(value),
            HeaderGate::Whole => true,
        };
        if !redact {
            return false;
        }
        let leading = segment.len() - segment.trim_start().len();
        let trailing = rest[..line_end].len() - rest[..line_end].trim_end().len();
        let value_start = q + leading;
        let value_end = q + line_end - trailing;
        self.flush_to(value_start);
        self.out.push_str(MASK);
        self.out.push_str(&self.text[value_end..q + line_end]);
        let consumed = q + line_end;
        self.copied = consumed;
        self.cursor = consumed;
        true
    }

    /// Value span: the matching closing quote when there is one, else up to
    /// the first delimiter (or whitespace for scheme values). The quoted scan
    /// honours `\` escapes (`"a\"b"` is one value) and looks across a
    /// bounded window of line breaks for the closing quote; every
    /// window is a constant, so a single-line document cannot make the scan
    /// quadratic. Returns `(body_end, closed)`.
    fn scan_value(&self, body_start: usize, quote: Option<u8>, scheme: bool) -> (usize, bool) {
        let rest = &self.text[body_start..];
        match quote {
            Some(quote) => {
                let limit = rest.len().min(QUOTED_SCAN_LIMIT);
                let bytes = rest.as_bytes();
                let mut close = None;
                let mut escaped = false;
                let mut i = 0usize;
                while i < limit {
                    let byte = bytes[i];
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == quote {
                        close = Some(i);
                        break;
                    }
                    i += 1;
                }
                match close {
                    Some(offset) => (body_start + offset, true),
                    None => {
                        // No closing quote: the body is the rest of the line,
                        // as before (a masking gate that fails there cannot
                        // hide a long secret, because a long all-token body
                        // passes the gate or is a digit/identifier band).
                        let line_end = rest.find(['\r', '\n']).unwrap_or(rest.len());
                        (body_start + line_end, false)
                    }
                }
            }
            None => {
                let end = if scheme {
                    rest.find(|c: char| c.is_whitespace() || is_value_delim(c))
                        .unwrap_or(rest.len())
                } else {
                    rest.find(is_value_delim).unwrap_or(rest.len())
                };
                (body_start + end, false)
            }
        }
    }

    /// `=`, `:`, `:=`, `%3D` or `%3A` at `p`.
    fn separator_at(&self, p: usize) -> Option<usize> {
        match self.bytes.get(p).copied()? {
            b'=' => Some(1),
            b':' if self.bytes.get(p + 1) == Some(&b'=') => Some(2),
            b':' => Some(1),
            b'%' if self.bytes.get(p + 1).map(u8::to_ascii_lowercase) == Some(b'3')
                && matches!(
                    self.bytes.get(p + 2).map(u8::to_ascii_lowercase),
                    Some(b'd') | Some(b'a')
                ) =>
            {
                Some(3)
            }
            _ => None,
        }
    }
}

/// ASCII `find` over bytes.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .find(|&index| &haystack[index..index + needle.len()] == needle)
}
