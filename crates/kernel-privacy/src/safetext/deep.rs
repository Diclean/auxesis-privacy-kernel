//! The `ner-gliner` Deep stack: a bounded model pass added on top of Standard,
//! and the combined name stack the eval measures.

use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;

use super::detector::{standard_builder, DetectionPair, Detector};
use super::prohibited::take_widened;
use super::report::DetectError;
use crate::email_layer::EmailLayer;
use crate::known_names::NameDictionaryError;
use crate::ner::GlinerRecognizer;
use crate::recognizer::{
    extend_hyphenated_persons, resolve_overlaps, span_is_well_formed, split_long_spans, Registry,
};
use crate::span::{EntityKind, Span};

#[cfg(feature = "ner-gliner")]
pub(super) struct DeepAdder {
    standard: Arc<dyn Detector>,
    deep: Arc<dyn Detector>,
}

#[cfg(feature = "ner-gliner")]
static DEEP_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "ner-gliner")]
impl DeepAdder {
    pub(super) fn new(standard: Arc<dyn Detector>, deep: Arc<dyn Detector>) -> Self {
        Self { standard, deep }
    }

    fn run(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        let standard = self.standard.detect(text)?;
        self.add_deep(text, standard)
    }

    fn add_deep(&self, text: &str, standard: Vec<Span>) -> Result<Vec<Span>, DetectError> {
        if text.len() > 64 * 1024 {
            return Ok(standard);
        }
        use std::sync::atomic::Ordering;
        if DEEP_BUSY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(standard);
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let deep = Arc::clone(&self.deep);
        let input = text.to_owned();
        if std::thread::Builder::new()
            .name("auxesis-deep-detector".into())
            .spawn(move || {
                let result = panic::catch_unwind(AssertUnwindSafe(|| deep.detect(&input)))
                    .unwrap_or(Err(DetectError::Panicked));
                DEEP_BUSY.store(false, Ordering::Release);
                let _ = tx.send(result);
            })
            .is_err()
        {
            DEEP_BUSY.store(false, Ordering::Release);
            return Ok(standard);
        }
        let Ok(Ok(spans)) = rx.recv_timeout(std::time::Duration::from_secs(5)) else {
            return Ok(standard);
        };
        let mut added: Vec<Span> = spans
            .into_iter()
            .filter(|span| span.kind.is_prohibited() && span_is_well_formed(text, span))
            .collect();
        let mut standard = standard;
        let widened = take_widened(&mut standard);
        added.extend(standard);
        let mut out = crate::ner::consolidate(added);
        out.extend(widened);
        Ok(out)
    }
}

#[cfg(feature = "ner-gliner")]
impl Detector for DeepAdder {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.run(text)
    }
    fn checks_names(&self) -> bool {
        self.standard.checks_names()
    }
    fn detect_covered(&self, text: &str) -> Result<(Vec<Span>, bool), DetectError> {
        Ok((self.run(text)?, self.standard.checks_names()))
    }
    fn detect_pair_covered(&self, first: &str, second: &str) -> Result<DetectionPair, DetectError> {
        let first_standard = self.standard.detect(first)?;
        let second_standard = self.standard.detect(second)?;
        let first_covered = self.standard.checks_names();
        let second_covered = first_covered;
        let first_result = (first_standard, first_covered);
        let second_result = (self.add_deep(second, second_standard)?, second_covered);
        Ok((first_result, second_result))
    }
    fn detect_patterns(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.run(text)
    }
    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        // Deep spans are masked from the original text before residue checking.
        // Keep residue on the deterministic stack so each Gate::text operation
        // runs the bounded model once and retains its single deadline.
        self.standard.residue(text)
    }
}

/// The best configuration the eval measures: deterministic candidates and
/// model spans go through the e-mail layer together, and the model's `PERSON`
/// spans seed name propagation.
#[cfg(feature = "ner-gliner")]
pub(super) struct NameStack {
    deterministic: Registry,
    layer: EmailLayer,
    model: GlinerRecognizer,
}

#[cfg(feature = "ner-gliner")]
impl NameStack {
    pub(super) fn new(model: GlinerRecognizer) -> Self {
        Self {
            deterministic: Registry::builder().with_all().without_email_layer().build(),
            layer: EmailLayer::new(),
            model,
        }
    }

    /// The Standard deterministic half plus the caller's known names. The
    /// e-mail layer runs once, below, with the model's spans in it.
    pub(super) fn with_names<I, S>(
        model: GlinerRecognizer,
        names: I,
    ) -> Result<Self, NameDictionaryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let (builder, _) = standard_builder(names)?;
        Ok(Self {
            deterministic: builder.without_email_layer().build(),
            layer: EmailLayer::new(),
            model,
        })
    }

    fn run(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        let mut candidates = self.deterministic.analyze(text);
        let predicted = self
            .model
            .analyze_report(text)
            .map_err(|_| DetectError::Names)?
            .spans;
        let seeds: Vec<Span> = predicted
            .iter()
            .filter(|span| span.kind == EntityKind::Person)
            .copied()
            .collect();
        candidates.extend(predicted);
        let layered = self.layer.apply(text, candidates, &seeds);
        let layered = extend_hyphenated_persons(text, layered);
        Ok(split_long_spans(text, resolve_overlaps(layered)))
    }
}

#[cfg(feature = "ner-gliner")]
impl Detector for NameStack {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        panic::catch_unwind(AssertUnwindSafe(|| self.run(text)))
            .map_err(|_| DetectError::Panicked)?
    }

    fn checks_names(&self) -> bool {
        true
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        // The deterministic half only: the model's name spans depend on their
        // context, as the e-mail layer's do (see `Detector::residue`).
        panic::catch_unwind(AssertUnwindSafe(|| self.deterministic.analyze(text)))
            .map_err(|_| DetectError::Panicked)
    }
}
