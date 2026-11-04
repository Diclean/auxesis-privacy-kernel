//! The layer's constructors and the `analyze`/`apply` pipeline.

use crate::company_id;
use crate::decode::DecodedText;
use crate::normalize::SharedViews;
use crate::public_terms::PublicTerms;
use crate::recognizer::Recognizer;
use crate::recognizers::email::EmailRecognizer;
use crate::span::{EntityKind, Span};

use super::lines::name_token_count;
use super::nameset::NameSet;
use super::signals::{is_private_signal, leaves_lone_name_in_clear, well_formed};
use super::EmailLayer;

impl EmailLayer {
    /// The layer with the built-in public-term list.
    pub fn new() -> Self {
        Self {
            public_terms: PublicTerms::builtin(),
            mask_first_names: false,
        }
    }

    /// Use a custom public-term allowlist.
    pub fn with_public_terms(mut self, public_terms: PublicTerms) -> Self {
        self.public_terms = public_terms;
        self
    }

    /// Turn bare-first-name masking back on (default `false`).
    ///
    /// The config key reserved for this switch is `[privacy]
    /// mask_first_names = false`. With it off, a lone token is left in clear only
    /// when `leaves_lone_name_in_clear` proves it is a bare given name: in the
    /// closed given-name lexicon, not in the surname lexicon, in a vocative or
    /// address position (a greeting or thanks word closing its clause, or a
    /// line-start comma) and outside signature or header context (`P.S.`/`PS`/`NB`
    /// lines included). Every other lone token stays masked; full names (2+
    /// tokens), signature and header names, known surnames, CJK names, names
    /// preceded by an honorific and ALL-CAPS surnames are always masked.
    pub fn with_first_names(mut self, mask_first_names: bool) -> Self {
        self.mask_first_names = mask_first_names;
        self
    }

    /// Whether bare first names are masked.
    pub fn masks_first_names(&self) -> bool {
        self.mask_first_names
    }

    /// Run the layer with no seeds from another recogniser.
    pub fn analyze(&self, text: &str) -> Vec<Span> {
        self.apply(text, Vec::new(), &[])
    }

    /// Add the layer's spans to `candidates` and drop public-term model spans.
    ///
    /// `seeds` must hold every `PERSON` span any mounted recogniser produced,
    /// including those below its threshold: a name the model found is evidence
    /// enough to mask its other occurrences.
    pub fn apply(&self, text: &str, candidates: Vec<Span>, seeds: &[Span]) -> Vec<Span> {
        let decoded = DecodedText::new(text);
        let _views = SharedViews::new(decoded.text());
        // One e-mail scan of the decoded view serves the seeds and propagation.
        let emails = EmailRecognizer::new().analyze(decoded.text());
        let mut names = NameSet::new(&self.public_terms);
        for seed in seeds {
            if seed.kind == EntityKind::Person
                && well_formed(text, seed)
                && self.keep_person_seed(text, seed, &names)
            {
                names.add_seed_text(&text[seed.start..seed.end]);
            }
        }

        let mut added = Vec::new();
        added.extend(self.emails_in_decoded(&decoded, &emails, &mut names));
        added.extend(self.header_spans(&decoded, &mut names));
        added.extend(self.greeting_spans(&decoded, &mut names));
        added.extend(self.signoff_spans(&decoded, &mut names));
        added.extend(self.line_name_spans(&decoded, &mut names));
        added.extend(self.speech_spans(&decoded, &mut names));
        added.extend(self.dob_spans(&decoded));
        added.extend(self.tracking_spans(text));
        added.extend(self.propagate(&decoded, &names, &emails));
        added.extend(company_id::recognize(text));

        let mut all = candidates;
        all.extend(added);
        if !self.mask_first_names {
            all.retain(|span| self.keep_person_span(text, span, &names));
        }
        self.filter_public(text, all)
    }

    /// Whether a `PERSON` seed may seed propagation.
    ///
    /// A single-token model `PERSON` only seeds when it is not a bare given
    /// name; with first names off a bare given name seeds nothing. Every rule
    /// seed, every multi-token model span, every signature/header name, every
    /// known surname and every CJK span always seeds.
    fn keep_person_seed(&self, text: &str, seed: &Span, names: &NameSet<'_>) -> bool {
        if self.mask_first_names {
            return true;
        }
        !self.drops_lone_given_name(text, seed, names)
    }

    /// Whether a `PERSON` candidate survives the bare-first-name rule.
    ///
    /// Only a single-token model span can be dropped: a full name, a rule span
    /// (a header display name is HIGH), a signature/header name, a known surname,
    /// a CJK name or an ALL-CAPS surname always survives.
    fn keep_person_span(&self, text: &str, span: &Span, names: &NameSet<'_>) -> bool {
        if self.mask_first_names || span.kind != EntityKind::Person {
            return true;
        }
        !self.drops_lone_given_name(text, span, names)
    }

    /// Whether a model `PERSON` span is a lone bare given name the default
    /// (first-names-off) policy drops.
    ///
    /// Every condition of [`leaves_lone_name_in_clear`] must hold to drop the
    /// span, including the vocative or address position; any doubt keeps it, so
    /// the rule fails toward masking. The span must additionally be a
    /// single-token `gliner` `PERSON` — a rule span or a name the lexicon does
    /// not know is never dropped this way.
    fn drops_lone_given_name(&self, text: &str, span: &Span, names: &NameSet<'_>) -> bool {
        if span.kind != EntityKind::Person || span.recognizer != "gliner" {
            return false;
        }
        if !well_formed(text, span) || name_token_count(text, span) != 1 {
            return false;
        }
        leaves_lone_name_in_clear(text, span.start, span.end, names)
    }
}

impl EmailLayer {
    /// Drop a model organisation or address span whose value is a public term.
    fn filter_public(&self, text: &str, spans: Vec<Span>) -> Vec<Span> {
        let private_present = spans.iter().any(|span| is_private_signal(span.kind));
        if private_present {
            return spans;
        }
        spans
            .into_iter()
            .filter(|span| {
                if !matches!(span.kind, EntityKind::Organization | EntityKind::Address) {
                    return true;
                }
                if !well_formed(text, span) {
                    return true;
                }
                !self.public_terms.contains(&text[span.start..span.end])
            })
            .collect()
    }

    /// Whether a rule-detected span may be emitted as a person.
    ///
    /// With bare-first-name masking on, every rule span is kept. With it off, a
    /// span of two or more name tokens is a full name. A lone token is kept
    /// unless [`leaves_lone_name_in_clear`] proves it is a bare given name: a
    /// known given name, not a known surname, in a vocative or address position,
    /// outside signature or header context. A token the lexicons do not know is
    /// **never** dropped here — an unknown rule token stays masked.
    pub(super) fn allow_lone_rule_span(
        &self,
        names: &NameSet<'_>,
        text: &str,
        start: usize,
        end: usize,
        token_count: usize,
    ) -> bool {
        if self.mask_first_names || token_count >= 2 {
            return true;
        }
        !leaves_lone_name_in_clear(text, start, end, names)
    }
}

impl Default for EmailLayer {
    fn default() -> Self {
        Self::new()
    }
}
