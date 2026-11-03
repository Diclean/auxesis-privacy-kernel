//! Span scoring: the gold/predicted counts, the overlap rule and the
//! per-language map the report prints.

use std::collections::BTreeMap;

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::span::EntityKind;
use serde_json::{json, Value};

#[derive(Default)]
pub(crate) struct Score {
    pub(crate) gold: usize,
    pub(crate) recalled: usize,
    pub(crate) predicted: usize,
    pub(crate) matched: usize,
}

impl Score {
    pub(crate) fn recall(&self) -> f64 {
        if self.gold == 0 {
            1.0
        } else {
            self.recalled as f64 / self.gold as f64
        }
    }
    pub(crate) fn precision(&self) -> f64 {
        if self.predicted == 0 {
            1.0
        } else {
            self.matched as f64 / self.predicted as f64
        }
    }
    pub(crate) fn add(&mut self, other: &Score) {
        self.gold += other.gold;
        self.recalled += other.recalled;
        self.predicted += other.predicted;
        self.matched += other.matched;
    }
}

pub(crate) fn overlap(left: &GoldSpan, right: &GoldSpan) -> bool {
    left.start < right.end && right.start < left.end
}

pub(crate) fn score(gold: &[GoldSpan], predicted: &[GoldSpan], only_person: bool) -> Score {
    let mut score = Score::default();
    for gold_span in gold {
        if only_person && gold_span.kind != EntityKind::Person {
            continue;
        }
        score.gold += 1;
        if predicted
            .iter()
            .any(|pred| pred.kind == gold_span.kind && overlap(pred, gold_span))
        {
            score.recalled += 1;
        }
    }
    for pred in predicted {
        if only_person && pred.kind != EntityKind::Person {
            continue;
        }
        score.predicted += 1;
        if gold
            .iter()
            .any(|gold_span| gold_span.kind == pred.kind && overlap(gold_span, pred))
        {
            score.matched += 1;
        }
    }
    score
}

pub(crate) fn percentile(values: &mut [f64], fraction: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let index = ((values.len() - 1) as f64 * fraction).round() as usize;
    values[index]
}

/// Per-language `{recall, precision, name_recall}` for the recogniser alone.
pub(crate) fn lang_map(entries: &BTreeMap<String, (Score, Score)>) -> Value {
    let mut map = serde_json::Map::new();
    for (lang, (all, names)) in entries {
        map.insert(
            lang.clone(),
            json!({
                "recall": all.recall(),
                "precision": all.precision(),
                "name_recall": names.recall(),
            }),
        );
    }
    Value::Object(map)
}
