//! The per-rule span producers: e-mail, header, greeting, sign-off, line name,
//! speech, birth date and tracking parameter.

use crate::decode::DecodedText;
use crate::public_terms::fold;
use crate::span::{EntityKind, Span};

use super::cues::{QUESTION_OPENERS, SPEECH_VERBS, TITLES, TRACKING_KEYS};
use super::display::{
    display_name, has_words_beyond_the_name, is_closing, is_latin_head, is_question_opening,
    opens_with_a_name, pick_rule_tokens, ps_rest, starts_with_greeting, subject_rest,
};
use super::function_words::FUNCTION_WORDS;
use super::lines::{
    content_after_prefix, find_date, is_token_boundary, line_ranges, lower_mapped,
    next_content_line, next_signoff_line, original_at, skip_separators, strip_quote_prefix,
    trim_signature_prefix, word_tokens, WordToken,
};
use super::mail_words::DOB_CUES;
use super::nameset::NameSet;
use super::signals::push_person;
use super::{EmailLayer, RULE_SCORE};

impl EmailLayer {
    /// Detect e-mail addresses on the decoded view and seed their local parts.
    pub(super) fn emails_in_decoded(
        &self,
        decoded: &DecodedText,
        emails: &[Span],
        names: &mut NameSet<'_>,
    ) -> Vec<Span> {
        let mut spans = Vec::new();
        for span in emails {
            let Some((start, end)) = decoded.source_bounds(span.start, span.end) else {
                continue;
            };
            let value = &decoded.text()[span.start..span.end];
            if let Some((local, _)) = value.split_once('@') {
                names.add_local_part(local);
            }
            spans.push(Span::new(
                EntityKind::Email,
                start,
                end,
                span.score,
                "email_layer",
            ));
        }
        spans
    }

    /// Display names in sender headers and reply lines.
    pub(super) fn header_spans(&self, decoded: &DecodedText, names: &mut NameSet<'_>) -> Vec<Span> {
        let text = decoded.text();
        let mut spans = Vec::new();
        for (line_start, line_end) in line_ranges(text) {
            let line = &text[line_start..line_end];
            let Some((start, end, tokens)) = display_name(line, names) else {
                continue;
            };
            let value = &text[line_start + start..line_start + end];
            if value.is_empty() {
                continue;
            }
            let raws: Vec<&str> = tokens
                .iter()
                .map(|token| &line[token.start..token.end])
                .collect();
            names.add_strong_phrase(&raws);
            if let Some((orig_start, orig_end)) =
                decoded.source_bounds(line_start + start, line_start + end)
            {
                spans.push(Span::new(
                    EntityKind::Person,
                    orig_start,
                    orig_end,
                    RULE_SCORE,
                    "email_layer_header",
                ));
            }
        }
        spans
    }

    /// Names named directly by a greeting.
    pub(super) fn greeting_spans(
        &self,
        decoded: &DecodedText,
        names: &mut NameSet<'_>,
    ) -> Vec<Span> {
        let text = decoded.text();
        let mut spans = Vec::new();
        for (line_start, line_end) in line_ranges(text) {
            let line = &text[line_start..line_end];
            let offset = strip_quote_prefix(line);
            let body = &line[offset..];
            let Some(greeting_end) = starts_with_greeting(body) else {
                continue;
            };
            let rest = &body[greeting_end..];
            let rest_offset = skip_separators(rest);
            let value = &rest[rest_offset..];
            let picked = pick_rule_tokens(value, names, 2);
            let (Some(first), Some(last_token)) = (picked.first(), picked.last()) else {
                continue;
            };
            // A greeting name is capitalised ("Bonjour Élise") or ends the greeting
            // phrase ("bonjour hugo,"). A lower-case run followed by more words is
            // the sentence ("Bonjour, ceci est un plan"), not a name.
            let capitalised = value[first.start..].starts_with(char::is_uppercase);
            let ends_phrase = value[last_token.end..]
                .trim_start()
                .chars()
                .next()
                .is_none_or(|ch| !ch.is_alphanumeric());
            if !capitalised && !ends_phrase {
                continue;
            }
            let raws: Vec<&str> = picked
                .iter()
                .map(|token| &rest[rest_offset + token.start..rest_offset + token.end])
                .collect();
            names.add_rule_phrase(&raws);
            let begin = line_start + offset + greeting_end + rest_offset + picked[0].start;
            let last =
                line_start + offset + greeting_end + rest_offset + picked.last().unwrap().end;
            if self.allow_lone_rule_span(names, text, begin, last, picked.len()) {
                push_person(decoded, begin, last, "email_layer_greeting", &mut spans);
            }
        }
        spans
    }

    /// The name line right after a closing, and the `ps:` author.
    pub(super) fn signoff_spans(
        &self,
        decoded: &DecodedText,
        names: &mut NameSet<'_>,
    ) -> Vec<Span> {
        let text = decoded.text();
        let lines = line_ranges(text);
        let mut spans = Vec::new();
        for (index, (line_start, line_end)) in lines.iter().enumerate() {
            let line = &text[*line_start..*line_end];
            let stripped = strip_quote_prefix(line);
            let candidate = line[stripped..].trim();
            if candidate.is_empty() {
                continue;
            }
            // `P.S.` / `PS` / `NB` author on the same line. `rest` runs to the end
            // of `line`, so `line.len() - rest.len()` is its exact offset.
            if let Some(rest) = ps_rest(line) {
                let offset = line.len() - rest.len();
                let picked = pick_rule_tokens(rest, names, 2);
                if !picked.is_empty() {
                    let raws: Vec<&str> = picked
                        .iter()
                        .map(|token| &rest[token.start..token.end])
                        .collect();
                    names.add_rule_phrase(&raws);
                    let begin = line_start + offset + picked[0].start;
                    let last = line_start + offset + picked.last().unwrap().end;
                    if self.allow_lone_rule_span(names, text, begin, last, picked.len()) {
                        push_person(decoded, begin, last, "email_layer_ps", &mut spans);
                    }
                }
                continue;
            }
            // A closing line or a `--` separator opens the signature block.
            let separator = matches!(candidate, "--" | "---" | "—" | "––");
            let closing = word_tokens(candidate).len() <= 6 && is_closing(candidate);
            if !closing && !separator {
                continue;
            }
            let Some((next_start, next_end)) = next_signoff_line(&lines, index + 1, text) else {
                continue;
            };
            let raw = &text[next_start..next_end];
            // The name is the part before a title or department that a comma
            // introduces ("Dr. H. Nel, Sonnekus Konsultante").
            let value = trim_signature_prefix(raw)
                .split([',', '\u{060C}'])
                .next()
                .unwrap_or("")
                .trim_end();
            if value.is_empty() {
                continue;
            }
            let tokens = word_tokens(value);
            if tokens.is_empty() || tokens.len() > 4 {
                continue;
            }
            if value.contains('@')
                || value.contains("://")
                || value.chars().any(|ch| ch.is_ascii_digit())
            {
                continue;
            }
            if !tokens.iter().any(|token| names.is_rule_name(token, value)) {
                continue;
            }
            names.add_rule_text(value, 4);
            let Some(offset) = raw.find(value) else {
                continue;
            };
            if self.allow_lone_rule_span(
                names,
                text,
                next_start + offset,
                next_start + offset + value.len(),
                tokens.len(),
            ) {
                push_person(
                    decoded,
                    next_start + offset,
                    next_start + offset + value.len(),
                    "email_layer_signoff",
                    &mut spans,
                );
            }
        }
        spans
    }

    /// A name at the very start of a line, followed by a comma.
    ///
    /// The body of a reply often opens with the addressee's first name right
    /// after the subject or header block (`Théo, peux-tu…`), in any language.
    pub(super) fn line_name_spans(
        &self,
        decoded: &DecodedText,
        names: &mut NameSet<'_>,
    ) -> Vec<Span> {
        let text = decoded.text();
        let mut spans = Vec::new();
        for (line_start, line_end) in line_ranges(text) {
            let line = &text[line_start..line_end];
            let (offset, value) = content_after_prefix(line);
            if value.is_empty() {
                continue;
            }
            // A name may open the line itself, or sit right after a subject
            // header's colon ("Subject: Priya, …").
            let (base, candidate) = match subject_rest(value) {
                Some(rest) => {
                    let trimmed = rest.trim_start();
                    let shift = value.len() - rest.len() + (rest.len() - trimmed.len());
                    (offset + shift, trimmed)
                }
                None => (offset, value),
            };
            // The name is followed by a comma, ASCII or Arabic, optionally after
            // one space; everything before it is the address.
            let Some(comma) = candidate
                .char_indices()
                .find(|(_, ch)| matches!(ch, ',' | '\u{060C}'))
                .map(|(index, _)| index)
            else {
                continue;
            };
            let head = candidate[..comma].trim_end();
            // Code, JSON and markup never open a name line: `{"path":"C:\x", …`
            // or `` `read_file` (risk: low), `` is a value, not a person.
            if head.is_empty() || head.contains(['{', '}', '[', ']', '\\', '`', '=']) {
                continue;
            }
            // A question or a request is not an address.
            if is_question_opening(head) {
                continue;
            }
            let picked = pick_rule_tokens(head, names, 4);
            if picked.is_empty() {
                continue;
            }
            // Latin script: the comma follows the name directly. A line whose
            // first comma sits deep in other words (`uid 12 · Thanks, …`, a
            // date `Thu, 15 Oct`) is a record or a sentence, not an address,
            // unless it opens with a full name (`Owen Calder works at …, `).
            if is_latin_head(head)
                && has_words_beyond_the_name(head, &picked)
                && !opens_with_a_name(head, &picked)
            {
                continue;
            }
            // A capitalized stop word can open a real first name ("Will,"), but
            // not when a second name-shaped word follows it: that is an article
            // phrase ("Le dossier,"), not a person.
            if picked.len() > 1
                && picked
                    .first()
                    .is_some_and(|token| names.is_weak_filtered(&token.folded))
            {
                continue;
            }
            let raws: Vec<&str> = picked
                .iter()
                .map(|token| &head[token.start..token.end])
                .collect();
            names.add_rule_phrase(&raws);
            // An ordinary name line masks just the name tokens. A short chat
            // clause that opens the body (`лол файл от павла опять не пришёл, …`)
            // has no comma-delimited name, so mask the whole clause: it is
            // bounded (<= 12 word tokens), carries no address, header or digit
            // field, and failing toward masking a clause that holds a lowercase
            // personal name beats leaking it. A sentence, an address line or a
            // data row stays on the picked name tokens only.
            let head_tokens = word_tokens(head);
            // Latin script: a vocative is at most three name-shaped words, none
            // a function or question word; a longer head is a sentence
            // (`Can you check my calendar, please?`). Other scripts keep the
            // short-clause rule.
            let plain_clause = head_tokens.len() <= 12
                && (!is_latin_head(head)
                    || (head_tokens.len() <= 3
                        && !head_tokens.iter().any(|token| {
                            FUNCTION_WORDS.contains(&token.folded.as_str())
                                || QUESTION_OPENERS.contains(&token.folded.as_str())
                        })))
                && !head
                    .chars()
                    .any(|ch| matches!(ch, '@' | ':' | '/' | '|' | '\\') || ch.is_ascii_digit());
            let (begin, end) = if plain_clause {
                (line_start + base, line_start + base + head.len())
            } else {
                (
                    line_start + base + picked[0].start,
                    line_start + base + picked.last().unwrap().end,
                )
            };
            let token_count = if plain_clause {
                head_tokens.len()
            } else {
                picked.len()
            };
            if self.allow_lone_rule_span(names, text, begin, end, token_count) {
                push_person(decoded, begin, end, "email_layer_line_name", &mut spans);
            }
        }
        spans
    }

    /// The speaker a speech verb names: `X said`, `X a dit`, `X сказала`,
    /// `X azt mondta`, `X het gesê`, or the verb-first Arabic `قال X`.
    pub(super) fn speech_spans(&self, decoded: &DecodedText, names: &mut NameSet<'_>) -> Vec<Span> {
        let text = decoded.text();
        let mut spans = Vec::new();
        for (line_start, line_end) in line_ranges(text) {
            let line = &text[line_start..line_end];
            let (lowered, map) = lower_mapped(line);
            if lowered.len() != line.len() {
                // `to_lowercase` changed the line's byte length (an exotic code
                // point): main skips the line, and so does this pass.
                continue;
            }
            for (verb, name_before) in SPEECH_VERBS {
                let Some(at) = lowered.find(*verb) else {
                    continue;
                };
                if !is_token_boundary(&lowered, at, verb.len()) {
                    continue;
                }
                // Equal lengths do not mean equal offsets (`İ` grows, `ẞ`
                // shrinks): slice `line` at the mapped bytes.
                let (Some(from), Some(to)) =
                    (original_at(&map, at), original_at(&map, at + verb.len()))
                else {
                    continue;
                };
                let value = if *name_before {
                    &line[..from]
                } else {
                    &line[to..]
                };
                let tokens = word_tokens(value);
                let ordered: Vec<WordToken> = if *name_before {
                    tokens.into_iter().rev().collect()
                } else {
                    tokens
                };
                // Walk out from the verb: skip a title or an initial, take the
                // name-shaped words, and stop at the first weaker word, so the
                // speaker is the run touching the verb.
                let mut picked: Vec<WordToken> = Vec::new();
                for token in ordered {
                    let folded = token.folded.as_str();
                    if TITLES.contains(&folded) || !NameSet::is_name_like(folded) {
                        continue;
                    }
                    let raw = &value[token.start..token.end];
                    if names.is_rule_name(&token, raw) {
                        picked.push(token);
                        if picked.len() >= 2 {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                if *name_before {
                    picked.reverse();
                }
                if picked.is_empty() {
                    continue;
                }
                let raws: Vec<&str> = picked
                    .iter()
                    .map(|token| &value[token.start..token.end])
                    .collect();
                names.add_rule_phrase(&raws);
                let base = if *name_before {
                    line_start
                } else {
                    line_start + to
                };
                let begin = base + picked[0].start;
                let last = base + picked.last().unwrap().end;
                if self.allow_lone_rule_span(names, text, begin, last, picked.len()) {
                    push_person(decoded, begin, last, "email_layer_speech", &mut spans);
                }
            }
        }
        spans
    }

    /// A birth date in a flattened table row, after a cue word.
    pub(super) fn dob_spans(&self, decoded: &DecodedText) -> Vec<Span> {
        let text = decoded.text();
        let lines = line_ranges(text);
        let mut spans = Vec::new();
        for (index, (line_start, line_end)) in lines.iter().enumerate() {
            let line = &text[*line_start..*line_end];
            let (lowered, map) = lower_mapped(line);
            let Some(end) = DOB_CUES
                .iter()
                .find_map(|cue| lowered.find(cue).map(|at| at + cue.len()))
            else {
                continue;
            };
            // A lowered offset is no `line` offset when lower-casing changes a
            // character's byte length (`İDOBé`): read on from the byte it maps
            // to and, as main did, from the same offset when that is a
            // character boundary of `line` too.
            let mapped = original_at(&map, end);
            let same = (mapped != Some(end) && line.is_char_boundary(end)).then_some(end);
            for cue in mapped.into_iter().chain(same) {
                let found = find_date(&line[cue..], line_start + cue).or_else(|| {
                    let (next_start, next_end) = next_content_line(&lines, index + 1, text)?;
                    find_date(&text[next_start..next_end], next_start)
                });
                if let Some((start, end)) = found {
                    if let Some((orig_start, orig_end)) = decoded.source_bounds(start, end) {
                        spans.push(Span::new(
                            EntityKind::DateOfBirth,
                            orig_start,
                            orig_end,
                            RULE_SCORE,
                            "email_layer_dob",
                        ));
                    }
                }
            }
        }
        spans
    }

    /// Mask the whole value of a tracking or unsubscribe query parameter.
    pub(super) fn tracking_spans(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for (url_start, url_end) in crate::decode::url_ranges(text) {
            let url = &text[url_start..url_end];
            let Some(question) = url.find('?') else {
                continue;
            };
            let mut offset = question + 1;
            for pair in url[question + 1..].split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    let folded = fold(key.trim());
                    if TRACKING_KEYS.contains(&folded.as_str()) && !value.is_empty() {
                        let value_start = url_start + offset + key.len() + 1;
                        let value_end = value_start + value.len();
                        let decoded = DecodedText::new(&text[value_start..value_end]);
                        let kind = if decoded.text().contains('@') {
                            EntityKind::Email
                        } else {
                            EntityKind::Person
                        };
                        spans.push(Span::new(
                            kind,
                            value_start,
                            value_end,
                            RULE_SCORE,
                            "email_layer_url",
                        ));
                    }
                }
                offset += pair.len() + 1;
            }
        }
        spans
    }
}
