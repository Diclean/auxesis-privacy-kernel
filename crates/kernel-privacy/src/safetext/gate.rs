//! The gate: one per grant, issuing the only text and JSON a provider may see.
//! Its constructors and public surface live here; masking is in `mask`, JSON in
//! `value`.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use kernel_core::privacy::{Grant, GrantPolicy};
use serde_json::Value;

#[cfg(feature = "ner-gliner")]
use super::deep::{DeepAdder, NameStack};
use super::detector::{
    default_detector, egress_detector, non_person_terms, without_names, Detector, StandardDetector,
    PRIVATE_DETECTOR,
};
use super::report::{DetectionReport, GateError};
use super::safe_text::{NameCoverage, SafeText, SafeValue};
use super::ASSISTANT_NAMES;
use crate::anonymize::Anonymizer;
use crate::known_names::NameDictionary;
#[cfg(feature = "ner-gliner")]
use crate::ner::GlinerRecognizer;

mod mask;
mod value;

/// The gate that issues [`SafeText`] and [`SafeValue`] for one [`Grant`].
///
/// A gate is built **from a grant**, so its policy (mask or pass through) is
/// the one `admit` decided, never a second switch a caller could flip. One
/// gate serves one session: its anonymizer keeps the session's value→token
/// table, so the same value gets the same token for as long as the key lasts.
///
/// There is no keyless or grantless constructor:
///
/// ```compile_fail,E0599
/// let _ = kernel_privacy::safetext::Gate::new([0u8; 32]);
/// ```
///
/// and the grant cannot be faked with a key or a mode:
///
/// ```compile_fail,E0308
/// let _ = kernel_privacy::safetext::Gate::for_grant(&[0u8; 32], [0u8; 32]);
/// ```
#[cfg_attr(
    not(feature = "test-util"),
    doc = "Without `test-util` no caller can inject a detector that approves everything:\n\n\
    ```compile_fail\n\
    struct Allow;\n\
    impl kernel_privacy::safetext::Detector for Allow {\n\
    fn detect(&self, _text: &str) -> Result<Vec<kernel_privacy::Span>, kernel_privacy::safetext::DetectError> {\n\
    Ok(Vec::new())\n\
    }\n\
    }\n\
    use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};\n\
    let ctx = Context { destination: Destination::LocalDisplay };\n\
    let Decision::Allow(grant) = admit(PathId::C9, PrivacyMode::Open, &ctx) else { unreachable!() };\n\
    let _ = kernel_privacy::safetext::Gate::for_tests(&grant, [0u8; 32], std::sync::Arc::new(Allow));\n\
    ```"
)]
pub struct Gate {
    detector: Arc<dyn Detector>,
    policy: GrantPolicy,
    /// The keyed pseudonyms. Present only when the policy masks; a passthrough
    /// gate needs no key and mints no token.
    anonymizer: Option<Anonymizer>,
    /// `(token, value)` pairs minted since the last [`Gate::take_minted`].
    /// They leave the gate only through that method, for the local display
    /// side; `Debug` never prints them.
    minted: Vec<(String, String)>,
    /// Whether names were covered on every string of the call in progress;
    /// `None` until a string is read (then the detector's standing claim holds).
    names_run: Option<bool>,
    /// Set by [`Gate::for_session_tokens`]: the tokens (`KIND_<hex>`, no
    /// delimiters) this session minted. The input already carries some of
    /// them; those pass through whole. Any other token-shaped text is ordinary
    /// text.
    session_tokens: Option<Arc<BTreeSet<String>>>,
    /// The markers the last passthrough mask wrote, as byte ranges of its text.
    removed: Vec<(usize, usize)>,
}

impl Gate {
    /// The one production constructor: the grant fixes the policy and `key`
    /// seeds the per-session pseudonyms.
    ///
    /// `GrantPolicy::Passthrough` runs the detectors and leaves ordinary values
    /// in clear (a prohibited class is replaced with its marker, never returned);
    /// `GrantPolicy::Tokenised` replaces every detected value with a keyed
    /// token.
    pub fn for_grant(grant: &Grant, key: [u8; 32]) -> Self {
        let detector = match grant.policy() {
            GrantPolicy::Tokenised => PRIVATE_DETECTOR
                .get_or_init(|| without_names(StandardDetector::new()))
                .clone(),
            GrantPolicy::Passthrough => default_detector(),
        };
        Self::with_detector_for_grant(grant, key, detector)
    }

    /// [`Gate::for_grant`] with the caller's known names (the contacts index)
    /// added to the Standard detector set. A name matches exactly: case- and
    /// accent-insensitive, whole-word, multi-token.
    pub fn for_grant_with_names<I, S>(
        grant: &Grant,
        key: [u8; 32],
        names: I,
    ) -> Result<Self, GateError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let detector = StandardDetector::with_names(names)?;
        let detector = egress_detector(grant, detector);
        Ok(Self::with_detector_for_grant(grant, key, detector))
    }

    /// [`Gate::for_grant_with_names`] over a dictionary the caller compiled
    /// once with [`NameDictionary::new`]. A service that gates many messages
    /// builds the dictionary at start-up and passes a clone of the `Arc` per
    /// gate; no gate recompiles the names.
    pub fn for_grant_with_dictionary(
        grant: &Grant,
        key: [u8; 32],
        dictionary: Arc<NameDictionary>,
    ) -> Self {
        let detector = egress_detector(grant, StandardDetector::with_dictionary(dictionary));
        Self::with_detector_for_grant(grant, key, detector).with_non_person_terms(ASSISTANT_NAMES)
    }

    /// Never tokenise `terms` (the assistant's own names, the configured agent
    /// ids) as a person. A name from the known-names dictionary still masks.
    #[must_use]
    pub fn with_non_person_terms<I, S>(mut self, terms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut folded = BTreeSet::new();
        for term in terms {
            let term = crate::public_terms::fold(term.as_ref());
            if !term.is_empty() {
                folded.insert(term);
            }
        }
        if !folded.is_empty() {
            self.detector = non_person_terms(self.detector, folded);
        }
        self
    }

    /// Add Deep model spans of prohibited Tier C kinds to the Standard gate.
    /// Model names and locations are deliberately ignored. A failed or slow
    /// model pass returns the Standard result unchanged.
    #[cfg(feature = "ner-gliner")]
    pub fn for_grant_with_deep_detector(
        grant: &Grant,
        key: [u8; 32],
        dictionary: Arc<NameDictionary>,
        deep: Arc<dyn Detector>,
    ) -> Self {
        let standard = egress_detector(grant, StandardDetector::with_dictionary(dictionary));
        Self::with_detector_for_grant(grant, key, Arc::new(DeepAdder::new(standard, deep)))
            .with_non_person_terms(ASSISTANT_NAMES)
    }

    /// A gate for a grant that never masks, without a session key.
    ///
    /// This is the constructor for a local destination (an MCP stdio child, a
    /// local display): the detectors run and the report is kept, but no token
    /// is minted, so no key is needed. A tokenising grant is refused
    /// ([`GateError::Key`]): masking without the session key would mint
    /// pseudonyms nobody can resolve.
    pub fn for_passthrough(grant: &Grant) -> Result<Self, GateError> {
        if grant.policy() != GrantPolicy::Passthrough {
            return Err(GateError::Key);
        }
        Ok(Self::with_detector_for_grant(
            grant,
            [0u8; 32],
            default_detector(),
        ))
    }

    fn with_detector_for_grant(grant: &Grant, key: [u8; 32], detector: Arc<dyn Detector>) -> Self {
        let policy = grant.policy();
        Self {
            detector,
            policy,
            anonymizer: match policy {
                GrantPolicy::Passthrough => None,
                GrantPolicy::Tokenised => Some(Anonymizer::new(key)),
            },
            minted: Vec::new(),
            names_run: None,
            session_tokens: None,
            removed: Vec::new(),
        }
    }

    /// A tokenising gate for a value the model wrote after reading only the
    /// session's tokens (an MCP call): each `⟦KIND_<hex>⟧` in `minted` (the
    /// tokens this session issued) already in it stays as it is, so the server
    /// receives the token and never the value. A token-shaped string the
    /// session never minted is ordinary text. Any value still in the clear is
    /// masked under a one-call key nobody can resolve. A passthrough grant is
    /// refused ([`GateError::Key`]).
    pub fn for_session_tokens(
        grant: &Grant,
        minted: Arc<BTreeSet<String>>,
    ) -> Result<Self, GateError> {
        if grant.policy() != GrantPolicy::Tokenised {
            return Err(GateError::Key);
        }
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|_| GateError::Key)?;
        let mut gate = Self::for_grant(grant, key);
        gate.session_tokens = Some(minted);
        Ok(gate)
    }

    /// A gate over an injected detector, for tests and `test-util` dependents:
    /// a production gate always runs the fixed registry.
    #[cfg(any(test, feature = "test-util"))]
    pub fn for_tests(grant: &Grant, key: [u8; 32], detector: Arc<dyn Detector>) -> Self {
        Self::with_detector_for_grant(grant, key, detector)
    }

    /// A gate whose names come from the local GLiNER model, unioned with the
    /// deterministic recognisers and the e-mail layer: the eval's best
    /// configuration.
    #[cfg(feature = "ner-gliner")]
    pub fn for_grant_with_gliner(grant: &Grant, key: [u8; 32], model: GlinerRecognizer) -> Self {
        Self::with_detector_for_grant(grant, key, Arc::new(NameStack::new(model)))
    }

    /// [`Gate::for_grant_with_gliner`] with the caller's known names unioned in,
    /// so Deep detection never detects less than Standard.
    #[cfg(feature = "ner-gliner")]
    pub fn for_grant_with_gliner_and_names<I, S>(
        grant: &Grant,
        key: [u8; 32],
        model: GlinerRecognizer,
        names: I,
    ) -> Result<Self, GateError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let stack = NameStack::with_names(model, names)?;
        Ok(Self::with_detector_for_grant(grant, key, Arc::new(stack)))
    }

    /// The policy this gate follows, from its grant.
    pub fn policy(&self) -> GrantPolicy {
        self.policy
    }

    /// Issue the text under the grant's policy, with the detection report.
    ///
    /// `Passthrough` returns the text with every detected prohibited-class value
    /// replaced by its `[<class> removed]` marker and the report of what private mode would have masked.
    /// `Tokenised` returns the masked text and refuses (`GateError`) when it
    /// cannot prove the output is clean.
    pub fn text(&mut self, text: &str) -> Result<(SafeText, DetectionReport), GateError> {
        self.names_run = None;
        self.removed.clear();
        let (masked, report) = self.mask(text)?;
        let names = self.coverage();
        let marks = match self.policy {
            GrantPolicy::Tokenised => super::seams::token_marks(&masked),
            GrantPolicy::Passthrough => std::mem::take(&mut self.removed),
        };
        Ok((
            SafeText {
                text: masked,
                names,
                marks,
                policy: self.policy,
            },
            report,
        ))
    }

    /// Keep `minted` (the tokens this session issued, `KIND_<hex>`) whole in
    /// what the gate issues next, as [`Gate::for_session_tokens`] does, but under
    /// this gate's own key: for text the model wrote after reading only the
    /// session's tokens. Its references then stay references, not literal text,
    /// and a value it wrote in clear is still masked. `None` goes back to
    /// reading every token-shaped string as text. A passthrough gate ignores it.
    pub fn keep_session_tokens(&mut self, minted: Option<Arc<BTreeSet<String>>>) {
        if self.policy == GrantPolicy::Tokenised {
            self.session_tokens = minted;
        }
    }

    /// The `(token, value)` pairs this gate minted since the last call, in mint
    /// order, and forgets them. This is the only way a value leaves the gate.
    pub fn take_minted(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.minted)
    }

    /// Issue a JSON value with every string key and string value masked under
    /// the grant's policy. Numbers, booleans and nulls pass unchanged. A string
    /// value whose key gives it a secret's context (the detector reads the pair
    /// `"<key>: <value>"`) is treated as one secret: a single token, or
    /// `SECRET_REMOVED` in open mode.
    pub fn value(&mut self, value: &Value) -> Result<(SafeValue, DetectionReport), GateError> {
        self.names_run = None;
        let (masked, report) = self.map_value(value)?;
        let names = self.coverage();
        Ok((
            SafeValue {
                value: masked,
                names,
            },
            report,
        ))
    }

    /// Whether this gate's output has names checked. Without a name detector
    /// both policies issue and mark it: a tokenising gate has still masked
    /// every pattern value (mail, phone, IBAN, card, ID, health, secret).
    fn coverage(&self) -> NameCoverage {
        if self
            .names_run
            .unwrap_or_else(|| self.detector.checks_names())
        {
            return NameCoverage::Checked;
        }
        NameCoverage::NotChecked
    }
}

impl fmt::Debug for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gate").finish_non_exhaustive()
    }
}
