//! The detection trait, the Standard detector stack every production gate runs,
//! and the private-mode wrapper that drops person and organisation names.

use std::collections::BTreeSet;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, OnceLock};

use kernel_core::privacy::{Grant, GrantPolicy};

use super::report::DetectError;
use crate::known_names::{NameDictionary, NameDictionaryError};
use crate::recognizer::{Registry, RegistryBuilder};
use crate::span::{EntityKind, Span};

type Detection = (Vec<Span>, bool);
pub(super) type DetectionPair = (Detection, Detection);

/// The local detection step, injected so the fail-closed path can be tested.
/// The default is the deterministic [`Registry`].
pub trait Detector: Send + Sync {
    /// Find every detectable value in `text`, or fail.
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError>;

    /// Whether this detector finds person and organisation names. The default
    /// is no: the deterministic registry finds a name only through the e-mail
    /// layer's cues.
    fn checks_names(&self) -> bool {
        false
    }

    /// [`Detector::detect`] plus whether names were covered on this very text.
    /// The default is the detector's standing claim; a two-pass detector whose
    /// second pass failed on this text says `false`.
    fn detect_covered(&self, text: &str) -> Result<(Vec<Span>, bool), DetectError> {
        Ok((self.detect(text)?, self.checks_names()))
    }

    /// Detect both token views. Composite detectors with expensive shared passes
    /// can override this to reuse one result across the pair.
    fn detect_pair_covered(&self, first: &str, second: &str) -> Result<DetectionPair, DetectError> {
        Ok((self.detect_covered(first)?, self.detect_covered(second)?))
    }

    /// Pattern values only, for a caller that does not need names (the JSON
    /// key-context probe). The default is [`Detector::detect`].
    fn detect_patterns(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.detect(text)
    }

    /// The values still detectable in the clear text of a masked string: the
    /// residue scan. It reads context-free values only by default; a detector
    /// whose name cues depend on context must not refuse text on them, since
    /// masking changes that context.
    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.detect(text)
    }
}

impl Detector for Registry {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        // A panic inside a recogniser is a detection error, never a clean pass.
        panic::catch_unwind(AssertUnwindSafe(|| self.analyze(text)))
            .map_err(|_| DetectError::Panicked)
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        panic::catch_unwind(AssertUnwindSafe(|| self.analyze_values(text)))
            .map_err(|_| DetectError::Panicked)
    }
}

/// The deterministic half shared by the Standard and Deep stacks: every
/// recogniser plus the caller's known-names dictionary, with the e-mail layer
/// left to the caller. Standard mounts the layer directly; Deep applies it once
/// with its model's `PERSON` spans as extra seeds. Both use this builder, so
/// Deep never detects less than Standard.
pub(super) fn standard_builder<I, S>(
    names: I,
) -> Result<(RegistryBuilder, bool), NameDictionaryError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    Ok(dictionary_builder(Arc::new(NameDictionary::new(names)?)))
}

/// [`standard_builder`] over a dictionary that is already compiled.
fn dictionary_builder(dictionary: Arc<NameDictionary>) -> (RegistryBuilder, bool) {
    let mounted = !dictionary.is_empty();
    let mut builder = Registry::builder().with_all();
    if mounted {
        builder = builder.with_recognizer(dictionary);
    }
    (builder, mounted)
}

/// The Standard detection set (D7): the deterministic recognisers with the
/// e-mail-aware layer, plus the caller's known-names dictionary when one is
/// supplied.
///
/// The dictionary is the only Tier H source in this build, so the detector
/// claims name coverage exactly when one is mounted. Without it a private gate
/// masks the pattern values and issues names-not-checked; Deep detection (feature
/// `ner-gliner`) adds its model on top.
pub struct StandardDetector {
    registry: Registry,
    /// Whether a name source is mounted.
    names: bool,
}

impl StandardDetector {
    /// Standard with no known-names dictionary: the deterministic recognisers
    /// and the e-mail layer, but no Tier H coverage.
    pub fn new() -> Self {
        Self {
            registry: Registry::builder().with_all().build(),
            names: false,
        }
    }

    /// Standard plus the caller's known names (Tier H). The dictionary is the
    /// only name source in this build, so its absence is what
    /// [`Detector::checks_names`] reports.
    pub fn with_names<I, S>(names: I) -> Result<Self, NameDictionaryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let (builder, names) = standard_builder(names)?;
        Ok(Self {
            registry: builder.build(),
            names,
        })
    }

    /// Standard plus a dictionary compiled once by the caller, shared rather
    /// than recompiled: the same matcher serves every detector built from it.
    pub fn with_dictionary(dictionary: Arc<NameDictionary>) -> Self {
        let (builder, names) = dictionary_builder(dictionary);
        Self {
            registry: builder.build(),
            names,
        }
    }
}

impl StandardDetector {
    /// This detector with no person or organisation span, dropped before the
    /// registry's overlap merge (see [`Registry::without_names`]).
    fn without_names(self) -> Self {
        Self {
            registry: self.registry.without_names(),
            names: self.names,
        }
    }
}

impl Default for StandardDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for StandardDetector {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        panic::catch_unwind(AssertUnwindSafe(|| self.registry.analyze_tagged(text)))
            .map_err(|_| DetectError::Panicked)
    }

    fn detect_patterns(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        panic::catch_unwind(AssertUnwindSafe(|| self.registry.analyze(text)))
            .map_err(|_| DetectError::Panicked)
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        panic::catch_unwind(AssertUnwindSafe(|| self.registry.analyze_values(text)))
            .map_err(|_| DetectError::Panicked)
    }

    fn checks_names(&self) -> bool {
        self.names
    }
}

/// The assistant's own names, never a person: the product and its chief.
pub const ASSISTANT_NAMES: &[&str] = &["Aux", "Auxesis"];

/// A detector that runs `inner` and passes every span list it returns through
/// `filter`, on every [`Detector`] method. Name coverage is `inner`'s, unchanged.
struct Filtered<F> {
    inner: Arc<dyn Detector>,
    filter: F,
}

impl<F> Detector for Filtered<F>
where
    F: Fn(&str, Vec<Span>) -> Vec<Span> + Send + Sync,
{
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok((self.filter)(text, self.inner.detect(text)?))
    }

    fn checks_names(&self) -> bool {
        self.inner.checks_names()
    }

    fn detect_covered(&self, text: &str) -> Result<(Vec<Span>, bool), DetectError> {
        let (spans, covered) = self.inner.detect_covered(text)?;
        Ok(((self.filter)(text, spans), covered))
    }

    fn detect_pair_covered(&self, first: &str, second: &str) -> Result<DetectionPair, DetectError> {
        let ((first_spans, first_covered), (second_spans, second_covered)) =
            self.inner.detect_pair_covered(first, second)?;
        Ok((
            ((self.filter)(first, first_spans), first_covered),
            ((self.filter)(second, second_spans), second_covered),
        ))
    }

    fn detect_patterns(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok((self.filter)(text, self.inner.detect_patterns(text)?))
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok((self.filter)(text, self.inner.residue(text)?))
    }
}

/// `inner` without the person spans naming the assistant itself (`terms` are
/// folded). The owner's own contacts always win: a span the known-names
/// dictionary produced stays masked, whatever the terms say.
pub(super) fn non_person_terms(
    inner: Arc<dyn Detector>,
    terms: BTreeSet<String>,
) -> Arc<dyn Detector> {
    Arc::new(Filtered {
        inner,
        filter: move |text: &str, mut spans: Vec<Span>| {
            spans.retain(|span| {
                span.kind != EntityKind::Person
                    || span.recognizer == crate::known_names::KNOWN_NAMES
                    || !text
                        .get(span.start..span.end)
                        .is_some_and(|value| terms.contains(&crate::public_terms::fold(value)))
            });
            spans
        },
    })
}

static DEFAULT_DETECTOR: OnceLock<Arc<StandardDetector>> = OnceLock::new();
pub(super) static PRIVATE_DETECTOR: OnceLock<Arc<dyn Detector>> = OnceLock::new();

/// The detector of a production gate for `grant`. Private mode hides no
/// person's or company's name: a tokenising gate drops every
/// name span, whatever found it (the known-names dictionary, the e-mail layer's
/// cues), and never runs the name model. The registry drops them before its
/// overlap merge, so a name that overlaps a card, an IBAN, an ID, a secret, a
/// health term, a birth date, an e-mail address or a phone number can neither
/// take that value's label nor remove its mask. Open mode is unchanged.
pub(super) fn egress_detector(grant: &Grant, standard: StandardDetector) -> Arc<dyn Detector> {
    match grant.policy() {
        GrantPolicy::Tokenised => without_names(standard),
        GrantPolicy::Passthrough => Arc::new(standard),
    }
}

/// The private-mode form of `standard`: names dropped before the merge, and
/// [`without_names_guard`] behind it.
pub(super) fn without_names(standard: StandardDetector) -> Arc<dyn Detector> {
    without_names_guard(Arc::new(standard.without_names()))
}

/// `inner` without its person and organisation spans: a second guard behind
/// [`Registry::without_names`], for any span a wrapped detector adds after the
/// registry ran.
fn without_names_guard(inner: Arc<dyn Detector>) -> Arc<dyn Detector> {
    Arc::new(Filtered {
        inner,
        filter: |_: &str, mut spans: Vec<Span>| {
            spans
                .retain(|span| !matches!(span.kind, EntityKind::Person | EntityKind::Organization));
            spans
        },
    })
}

pub(super) fn default_detector() -> Arc<dyn Detector> {
    DEFAULT_DETECTOR
        .get_or_init(|| Arc::new(StandardDetector::new()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::known_names::KNOWN_NAMES;

    /// A fixed span list on every method, with name coverage claimed.
    struct Fixed;

    impl Detector for Fixed {
        fn detect(&self, _: &str) -> Result<Vec<Span>, DetectError> {
            Ok(vec![
                Span::new(EntityKind::Person, 0, 3, 0.9, "stub"),
                Span::new(EntityKind::Person, 4, 9, 0.9, KNOWN_NAMES),
                Span::new(EntityKind::Organization, 10, 13, 0.8, "stub"),
                Span::new(EntityKind::Email, 14, 21, 1.0, "stub"),
            ])
        }

        fn checks_names(&self) -> bool {
            true
        }
    }

    /// Both guards filter every method's spans the same way and keep the
    /// inner detector's name coverage.
    #[test]
    fn filtered_guards_apply_on_every_method() {
        let text = "Aux Alice Acm a@b.co";
        let terms = BTreeSet::from(["aux".to_string(), "alice".to_string()]);
        let terms = non_person_terms(Arc::new(Fixed), terms);
        let names = without_names_guard(Arc::new(Fixed));
        for (detector, kept) in [(terms, vec![4, 10, 14]), (names, vec![14])] {
            let ((first, covered), (second, _)) = detector.detect_pair_covered(text, text).unwrap();
            assert!(covered && detector.checks_names());
            let (spans, covered) = detector.detect_covered(text).unwrap();
            assert!(covered);
            let patterns = detector.detect_patterns(text).unwrap();
            let residue = detector.residue(text).unwrap();
            let detect = detector.detect(text).unwrap();
            for spans in [first, second, spans, patterns, residue, detect] {
                let starts: Vec<usize> = spans.iter().map(|span| span.start).collect();
                assert_eq!(starts, kept);
            }
        }
    }
}
