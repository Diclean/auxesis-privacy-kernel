//! Code runs after a recovery-code cue: groups, shapes and the run state.

use super::keys::is_prose_word;

/// Groups one run span holds at most, and its most bytes.
const MAX_RUN_GROUPS: usize = 16;
const MAX_RUN_BYTES: usize = 256;

/// State shared by all code fragments after one recovery-code cue.
#[derive(Default)]
pub(super) struct RecoveryRun {
    group_len: Option<usize>,
    /// The run length, capped for same-shape letter-only continuations.
    groups: usize,
    confirmed: bool,
    digit_seen: bool,
    pending: Vec<(usize, usize)>,
}

impl RecoveryRun {
    fn reset(&mut self) {
        self.group_len = None;
        self.groups = 0;
        self.confirmed = false;
        self.digit_seen = false;
        self.pending.clear();
    }

    fn add_groups(&mut self, count: usize) {
        self.groups = self.groups.saturating_add(count).min(MAX_RUN_GROUPS);
    }

    pub(super) fn active(&self) -> bool {
        self.group_len.is_some() && self.groups > 0
    }
}

/// The groups of one word of a code run (`7KQ2`, `7KQ2-9XZ1`, `7KQ2-` before a
/// line break), or `None` when a group is not 4 to 12 ASCII letters and digits
/// (3 to 12 inside a dashed word, so `blue-otter-472` is one Wi-Fi key).
fn run_groups(body: &str) -> Option<usize> {
    let body = body.strip_suffix('-').unwrap_or(body);
    let least = if body.contains('-') { 3 } else { 4 };
    let mut groups = 0;
    for group in body.split('-') {
        if !(least..=12).contains(&group.len()) || !group.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return None;
        }
        groups += 1;
    }
    Some(groups)
}

/// The code runs after an [`EXTRA_KEY_RE`](super::keys::EXTRA_KEY_RE) key ending at `from`: a line break
/// and one blank line may follow the key and its `:` or `,`, then a
/// [`code_run`] (`Recovery codes:\n7KQ2 9XZ1\nM4P8-R6T3`). Returns where the scan stopped,
/// so a later key inside the run is not read again (linear).
pub(super) fn group_runs(
    text: &str,
    from: usize,
    recovery_codes: bool,
    recovery: &mut RecoveryRun,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    let bytes = text.as_bytes();
    let mut at = from;
    while matches!(bytes.get(at), Some(b' ' | b'\t')) {
        at += 1;
    }
    if matches!(bytes.get(at), Some(b':' | b'=' | b',')) {
        at += 1;
    } else if text[at..].starts_with('：') {
        at += '：'.len_utf8();
    }
    for _ in 0..2 {
        while matches!(bytes.get(at), Some(b' ' | b'\t')) {
            at += 1;
        }
        if text[at..].starts_with("\r\n") {
            at += 2;
        } else if text[at..].starts_with('\n') {
            at += 1;
        }
    }
    while matches!(bytes.get(at), Some(b' ' | b'\t')) {
        at += 1;
    }
    code_run(text, at, true, recovery_codes, recovery, spans).max(from)
}

/// One run of groups from `at`, joined by one space, a `-` or a line break. A
/// blank line, a lowercase word of five letters or more, a later word of
/// lowercase letters only (except a same-length recovery-code group within the
/// group cap), a [`PROSE_WORDS`](super::keys::PROSE_WORDS) word (`R6T3 Thanks`), or any other word ends
/// the run; a `|` or `,` ends a word, and a line break ends the run unless
/// `lines`. Outside recovery cues, a run with no digit is no code. Each span
/// holds at most [`MAX_RUN_GROUPS`] groups and [`MAX_RUN_BYTES`] bytes, and a
/// longer run goes on in a next span. Returns where the run ended.
pub(super) fn code_run(
    text: &str,
    mut at: usize,
    lines: bool,
    recovery_codes: bool,
    recovery: &mut RecoveryRun,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    if recovery_codes {
        return recovery_code_run(text, at, lines, !lines, recovery, spans);
    }
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let (mut start, mut end, mut groups, mut digit, mut first) = (at, at, 0, false, true);
    loop {
        let len = bytes[at..]
            .iter()
            .take(MAX_RUN_BYTES + 1)
            .take_while(|b| !b.is_ascii_whitespace() && !matches!(b, b'|' | b','))
            .count();
        if len == 0 || len > MAX_RUN_BYTES || !text.is_char_boundary(at + len) {
            break;
        }
        let word = &text[at..at + len];
        let body = word.trim_end_matches(['.', ',', ';', ')']);
        let lower = !body.is_empty() && body.bytes().all(|b| b.is_ascii_lowercase());
        let Some(count) = run_groups(body) else { break };
        if lower && (body.len() >= 5 || !first) {
            break;
        }
        if is_prose_word(body) {
            break;
        }
        if groups + count > MAX_RUN_GROUPS || at + body.len() - start > MAX_RUN_BYTES {
            if end > start {
                found.push((start, end));
            }
            (start, groups) = (at, 0);
        }
        groups += count;
        digit |= body.bytes().any(|b| b.is_ascii_digit());
        end = at + body.len();
        at += len;
        first = false;
        if body.len() < word.len() {
            break;
        }
        let next = if bytes.get(at) == Some(&b' ') {
            1
        } else if lines && text[at..].starts_with("\r\n") {
            2
        } else if lines && bytes.get(at) == Some(&b'\n') {
            1
        } else {
            break;
        };
        if bytes.get(at + next).is_none_or(u8::is_ascii_whitespace) {
            break;
        }
        at += next;
    }
    if end > start {
        found.push((start, end));
    }
    if digit {
        spans.extend(found);
    }
    end
}

/// Reads recovery-code fragments while retaining their shape across spaces,
/// comma cells, and list items. Three same-length letters-only groups confirm
/// an otherwise digitless run; until then their spans stay bounded in `pending`.
fn recovery_code_run(
    text: &str,
    mut at: usize,
    lines: bool,
    strict_shape: bool,
    recovery: &mut RecoveryRun,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    let bytes = text.as_bytes();
    let mut end = at;
    loop {
        let len = bytes[at..]
            .iter()
            .take(MAX_RUN_BYTES + 1)
            .take_while(|b| !b.is_ascii_whitespace() && !matches!(b, b'|' | b','))
            .count();
        if len == 0 || len > MAX_RUN_BYTES || !text.is_char_boundary(at + len) {
            break;
        }
        let word = &text[at..at + len];
        let body = word.trim_end_matches(['.', ',', ';', ')']);
        let Some(count) = run_groups(body) else {
            recovery.reset();
            break;
        };
        if is_prose_word(body) {
            recovery.reset();
            break;
        }

        let parts = body.strip_suffix('-').unwrap_or(body);
        let group_len = parts.split('-').next().map_or(0, str::len);
        let same_part_lengths = parts.split('-').all(|group| group.len() == group_len);
        let letters_only = same_part_lengths
            && !parts.is_empty()
            && parts
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic() || byte == b'-');
        let lower = !body.is_empty() && body.bytes().all(|byte| byte.is_ascii_lowercase());
        let has_digit = body.bytes().any(|byte| byte.is_ascii_digit());
        let bounded_letters = letters_only && (!recovery.digit_seen || lower || strict_shape);
        if bounded_letters && recovery.groups.saturating_add(count) > MAX_RUN_GROUPS {
            break;
        }

        if letters_only {
            if recovery.group_len.is_none() {
                recovery.group_len = Some(group_len);
            }
            let same_length = recovery.group_len == Some(group_len);
            if !recovery.confirmed && !same_length {
                recovery.reset();
                break;
            }
            if recovery.confirmed && (!recovery.digit_seen || lower || strict_shape) && !same_length
            {
                recovery.reset();
                break;
            }
            // Uppercase and mixed-case letter groups already continued a
            // digit-backed run before this recovery-specific extension.
            recovery.add_groups(count);
            let group_end = at + body.len();
            if recovery.confirmed {
                spans.push((at, group_end));
            } else {
                recovery.pending.push((at, group_end));
                if recovery.groups >= 3 {
                    recovery.confirmed = true;
                    spans.append(&mut recovery.pending);
                }
            }
            end = group_end;
        } else {
            if !recovery.confirmed
                && recovery
                    .group_len
                    .is_some_and(|expected| expected != group_len)
            {
                recovery.reset();
            }
            recovery.group_len.get_or_insert(group_len);
            recovery.add_groups(count);
            if has_digit {
                recovery.confirmed = true;
                recovery.digit_seen = true;
                spans.append(&mut recovery.pending);
            }
            if recovery.confirmed {
                spans.push((at, at + body.len()));
            } else {
                recovery.reset();
                break;
            }
            end = at + body.len();
        }

        at += len;
        if body.len() < word.len() {
            recovery.reset();
            break;
        }
        let next = if bytes.get(at) == Some(&b' ') {
            1
        } else if lines && text[at..].starts_with("\r\n") {
            2
        } else if lines && bytes.get(at) == Some(&b'\n') {
            1
        } else {
            break;
        };
        if bytes.get(at + next).is_none_or(u8::is_ascii_whitespace) {
            break;
        }
        at += next;
    }
    end
}
