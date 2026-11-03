//! The recognisers of the EU national and tax identifiers.

use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

use super::{spans_for, KIND, RULES, RULES_1C};

/// Build one country recogniser: the same plumbing for every rule.
macro_rules! eu_recognizer {
    ($name:ident, $rule:expr) => {
        /// The recogniser of one EU identifier.
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;
        impl $name {
            /// Build the recognise.
            pub fn new() -> Self {
                Self
            }
        }
        impl Recognizer for $name {
            fn kinds(&self) -> &[EntityKind] {
                &[KIND]
            }
            fn analyze(&self, text: &str) -> Vec<Span> {
                spans_for(std::slice::from_ref($rule), text)
            }
            fn name(&self) -> &'static str {
                $rule.0
            }
        }
    };
}

eu_recognizer!(DeSteuerIdRecognizer, &RULES[0]);
eu_recognizer!(EsDniRecognizer, &RULES[1]);
eu_recognizer!(ItCodiceFiscaleRecognizer, &RULES[2]);
eu_recognizer!(NlBsnRecognizer, &RULES[3]);
eu_recognizer!(BeNationalNumberRecognizer, &RULES[4]);
eu_recognizer!(PlPeselRecognizer, &RULES[5]);
eu_recognizer!(PtNifRecognizer, &RULES[6]);
eu_recognizer!(AtSvNrRecognizer, &RULES[7]);
eu_recognizer!(IePpsnRecognizer, &RULES[8]);
eu_recognizer!(SePersonnummerRecognizer, &RULES[9]);

/// The recogniser of EU-KERNEL-1c: the Romanian CNP, the Czech and Slovak
/// rodné číslo, the Greek AFM and AMKA and the Bulgarian EGN, read over one
/// body. Every span names the rule that read it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Eu1cRecognizer;

impl Eu1cRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for Eu1cRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[KIND]
    }
    fn analyze(&self, text: &str) -> Vec<Span> {
        spans_for(&RULES_1C, text)
    }
    fn name(&self) -> &'static str {
        "eu_ids_1c"
    }
}
