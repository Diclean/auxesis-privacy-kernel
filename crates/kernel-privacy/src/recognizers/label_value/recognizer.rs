//! The label-value recogniser and its per-label dispatch.

use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

use super::blood::{blood, blood_column, glued_blood};
use super::cues::{health_cued, inside_word, passport_covers};
use super::lexicon::{Class, LEXICON};
use super::links::{link, numbered};
use super::table::cookie_pairs;
use super::text::fold;
use super::values::{cookie, is_date, number, secret, spaced_passport};

/// The name echoed in [`Span::recognizer`].
pub(super) const NAME: &str = "label_value";

/// The recogniser for a sensitive label followed by its value.
#[derive(Clone, Copy, Debug, Default)]
pub struct LabelValueRecognizer;

impl LabelValueRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for LabelValueRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[
            EntityKind::Secret,
            EntityKind::NationalId,
            EntityKind::Health,
        ]
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let lexicon = &*LEXICON;
        let (folded, map) = fold(text);
        let newlines: Vec<usize> = text.match_indices('\n').map(|(at, _)| at).collect();
        let equals: Vec<usize> = text.match_indices('=').map(|(at, _)| at).collect();
        // A value or token already read ends at `reach`: a label inside it is part of
        // it, so no byte is read twice (linear without a value cap).
        let (mut spans, mut reach) = (Vec::new(), 0);
        // Rows a blood column already read end at `rows`: a header among them is
        // not read again, so each row is read once.
        let mut rows = 0;
        for hit in lexicon.automaton.find_iter(&folded) {
            let label = &lexicon.labels[hit.pattern().as_usize()];
            if map[hit.start()] < reach {
                continue;
            }
            let before = folded[..hit.start()].chars().next_back();
            let after = folded[hit.end()..].chars().next();
            if inside_word(text, map[hit.start()])
                || !label.cjk_start && before.is_some_and(char::is_alphanumeric)
            {
                continue;
            }
            if label.class == Class::Blood {
                let (start, end) = (map[hit.start()], map[hit.end()]);
                let next = newlines.partition_point(|&at| at < start);
                let line = (
                    next.checked_sub(1).map_or(0, |n| newlines[n] + 1),
                    newlines.get(next).map_or(text.len(), |&at| at),
                );
                spans.extend(blood_column(text, (start, end), line, &mut rows));
            }
            if !label.cjk_end && after.is_some_and(char::is_alphanumeric) {
                // A blood group glued to its label, maybe behind a short tag
                // (`Blood typerefAB negative`).
                if let Some(end) = (label.class == Class::Blood)
                    .then(|| glued_blood(text, map[hit.end()]))
                    .flatten()
                {
                    spans.push(Span::new(
                        EntityKind::Health,
                        map[hit.end()],
                        end,
                        1.0,
                        NAME,
                    ));
                    reach = reach.max(end);
                }
                continue;
            }
            let wide = !matches!(label.class, Class::Secret | Class::Cookie);
            let aside = label.class == Class::Id;
            let Some((at, strong, prose, crossed)) = link(&folded, hit.end(), wide, aside) else {
                continue;
            };
            if (label.punct && !strong)
                || (label.numbered && !numbered(&folded[..hit.start()], &folded[hit.end()..]))
            {
                continue;
            }
            let start = map[at];
            let line = newlines
                .get(newlines.partition_point(|&at| at < start))
                .map_or(text.len(), |&at| at);
            let found = match label.class {
                Class::Secret => {
                    let (end, read) = secret(text, start, line, prose);
                    reach = reach.max(read);
                    end
                }
                Class::Cookie => {
                    let eq = equals.get(equals.partition_point(|&at| at < start));
                    eq.is_some_and(|&at| at < line)
                        .then(|| cookie(text, start, line))
                        .flatten()
                }
                Class::Id => {
                    let read = |start: usize| {
                        number(text, start, 5)
                            .or_else(|| {
                                spaced_passport(text, &folded[hit.start()..hit.end()], start)
                            })
                            .filter(|&end| !passport_covers(text, map[hit.start()], start, end))
                            .filter(|&end| {
                                !((label.numbered || crossed) && is_date(&text[start..end]))
                            })
                    };
                    read(start)
                }
                Class::Health => number(text, start, 4),
                Class::Blood => blood(text, start, strong),
                Class::Member => {
                    number(text, start, 4).filter(|&end| health_cued(text, map[hit.start()], end))
                }
            };
            if let Some(end) = found {
                let kind = match label.class {
                    Class::Secret | Class::Cookie => EntityKind::Secret,
                    Class::Id => EntityKind::NationalId,
                    Class::Health | Class::Blood | Class::Member => EntityKind::Health,
                };
                spans.push(Span::new(kind, start, end, 1.0, NAME));
                // A label inside a crossed aside is still read (`licence number
                // (password/…): …`): the value is short, so the
                // rescan stays bounded.
                if !crossed {
                    reach = reach.max(end);
                }
            }
        }
        spans.extend(cookie_pairs(text, &folded, &map));
        spans
    }
}
