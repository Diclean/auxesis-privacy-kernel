//! The recogniser the registry and the gate use.

use std::sync::Mutex;

use gliner2_rs::{Gliner2, Options};

use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

use super::config::GlinerConfig;
use super::consolidate::consolidate;
use super::error::GlinerError;
use super::labels::label_kind;

/// What one [`GlinerRecognizer::analyze_report`] call produced.
#[derive(Clone, Debug, Default)]
pub struct GlinerReport {
    /// The model's spans, ordered by start offset and never overlapping.
    pub spans: Vec<Span>,
    /// Spans the model returned whose bytes did not match the source text.
    pub dropped: usize,
    /// Number of token windows the text was split into (`1` when it fit).
    pub chunks: usize,
}

/// A local GLiNER2-PII recogniser.
pub struct GlinerRecognizer {
    model: Gliner2,
    config: GlinerConfig,
    kinds: Vec<EntityKind>,
    failure: Mutex<Option<GlinerError>>,
}

impl GlinerRecognizer {
    /// Load the ONNX graph and the fast tokenizer from `config.model_dir`.
    ///
    /// A missing file, a bad graph or a bad tokenizer is a [`GlinerError`]; the
    /// recogniser is never built in a state that would answer "no entities".
    pub fn load(config: GlinerConfig) -> Result<Self, GlinerError> {
        if config.threshold <= 0.0 || config.threshold > 1.0 {
            return Err(GlinerError::Config(format!(
                "threshold {} is outside 0.0..=1.0",
                config.threshold
            )));
        }
        if config.labels.is_empty() {
            return Err(GlinerError::Config("no entity labels".to_string()));
        }

        let options = Options {
            label_thresholds: config
                .label_thresholds
                .iter()
                .map(|(label, threshold)| (label.to_string(), *threshold))
                .collect(),
            max_width: config.max_width,
            chunk_tokens: config.chunk_tokens,
            chunk_overlap: config.chunk_overlap,
            ort_dylib: config.ort_dylib.clone(),
        };
        let model = Gliner2::load_paths(
            config.model_dir.join(&config.onnx_file),
            config.model_dir.join(&config.tokenizer_file),
            &options,
        )?;

        let mut kinds: Vec<EntityKind> = Vec::new();
        for label in &config.labels {
            if let Some(kind) = label_kind(label) {
                if !kinds.contains(&kind) {
                    kinds.push(kind);
                }
            }
        }

        Ok(Self {
            model,
            config,
            kinds,
            failure: Mutex::new(None),
        })
    }

    /// The configuration this recogniser was built with.
    pub fn config(&self) -> &GlinerConfig {
        &self.config
    }

    /// The error recorded by the infallible [`Recognizer::analyze`] adapter, if
    /// any, clearing it. `analyze_report` does not record anything.
    pub fn take_error(&self) -> Option<GlinerError> {
        self.failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    /// Run the model over `text`, chunking it when it does not fit one window.
    ///
    /// Returns the verified, non-overlapping spans plus the number of model
    /// spans dropped for not matching the source bytes. Any load, tokenisation
    /// or inference failure is a [`GlinerError`].
    pub fn analyze_report(&self, text: &str) -> Result<GlinerReport, GlinerError> {
        let labels: Vec<&str> = self.config.labels.clone();
        let extraction = self
            .model
            .extract_report(text, &labels, self.config.threshold)?;
        let spans: Vec<Span> = extraction
            .entities
            .into_iter()
            .filter_map(|entity| {
                let kind = label_kind(&entity.label)?;
                Some(Span::new(
                    kind,
                    entity.start,
                    entity.end,
                    entity.score,
                    "gliner",
                ))
            })
            .collect();
        Ok(GlinerReport {
            spans: consolidate(spans),
            dropped: extraction.dropped,
            chunks: extraction.chunks,
        })
    }

    /// [`Self::analyze_report`] with only the spans.
    pub fn recognize(&self, text: &str) -> Result<Vec<Span>, GlinerError> {
        Ok(self.analyze_report(text)?.spans)
    }
}

impl Recognizer for GlinerRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &self.kinds
    }

    /// The infallible trait adapter: fail toward masking.
    ///
    /// On any [`GlinerError`] this masks the whole text as one `NATIONAL_ID`
    /// span (which the registry then splits) and stores the error, retrievable
    /// with [`GlinerRecognizer::take_error`]. It never reports "no entities" on
    /// error. Prefer [`GlinerRecognizer::analyze_report`] where the error can
    /// be propagated.
    fn analyze(&self, text: &str) -> Vec<Span> {
        match self.analyze_report(text) {
            Ok(report) => report.spans,
            Err(error) => {
                *self
                    .failure
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
                vec![Span::new(
                    EntityKind::NationalId,
                    0,
                    text.len(),
                    1.0,
                    "gliner",
                )]
            }
        }
    }

    fn name(&self) -> &'static str {
        "gliner"
    }

    /// A model is not a checksum rule, but its scores are already calibrated
    /// probabilities, so the registry must not relabel every span it emits.
    fn verified(&self) -> bool {
        true
    }

    /// A model is opt-in: the default registry stays deterministic and offline.
    fn enabled_by_default(&self) -> bool {
        false
    }
}

/// As an egress-gate detector the model only adds prohibited kinds; names and
/// other ordinary labels stay with the registry and CRM callers of
/// [`GlinerRecognizer::recognize`], which need them.
impl crate::safetext::Detector for GlinerRecognizer {
    fn detect(&self, text: &str) -> Result<Vec<Span>, crate::safetext::DetectError> {
        self.recognize(text)
            .map(|spans| {
                spans
                    .into_iter()
                    .filter(|span| span.kind.is_prohibited())
                    .collect()
            })
            .map_err(|_| crate::safetext::DetectError::Names)
    }
}
