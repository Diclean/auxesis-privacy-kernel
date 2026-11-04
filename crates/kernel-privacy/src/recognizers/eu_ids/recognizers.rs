//! The recognisers of the EU national and tax identifiers.

use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

use super::{spans_for, Rule, KIND, RULES, RULES_1C};

/// The rule named `name`. A recogniser names its rule, never its position in
/// [`RULES`], so reordering the table cannot swap two rules.
fn named(name: &str) -> &'static [Rule] {
    let rule = RULES
        .iter()
        .find(|rule| rule.0 == name)
        .unwrap_or_else(|| panic!("no EU rule named {name}"));
    std::slice::from_ref(rule)
}

/// Declare one public recogniser over `rules` (one rule, or a group read over
/// one body). The rule is named, never indexed by position.
macro_rules! eu_recognizer {
    ($name:ident, $label:literal) => {
        eu_recognizer!($name, $label, named($label));
    };
    ($(#[$meta:meta])* $name:ident, $label:literal, $rules:expr) => {
        /// The recogniser of one EU identifier.
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl $name {
            /// Build the recogniser.
            pub fn new() -> Self {
                Self
            }
        }

        impl Recognizer for $name {
            fn kinds(&self) -> &[EntityKind] {
                &[KIND]
            }

            fn analyze(&self, text: &str) -> Vec<Span> {
                spans_for($rules, text)
            }

            fn name(&self) -> &'static str {
                $label
            }
        }
    };
}

eu_recognizer!(DeSteuerIdRecognizer, "de_steuer_id");
eu_recognizer!(EsDniRecognizer, "es_dni");
eu_recognizer!(ItCodiceFiscaleRecognizer, "it_codice_fiscale");
eu_recognizer!(NlBsnRecognizer, "nl_bsn");
eu_recognizer!(BeNationalNumberRecognizer, "be_national_number");
eu_recognizer!(PlPeselRecognizer, "pl_pesel");
eu_recognizer!(PtNifRecognizer, "pt_nif");
eu_recognizer!(AtSvNrRecognizer, "at_sv_nr");
eu_recognizer!(IePpsnRecognizer, "ie_ppsn");
eu_recognizer!(SePersonnummerRecognizer, "se_personnummer");

eu_recognizer!(
    /// The recogniser of this group: the Romanian CNP, the Czech and Slovak
    /// rodné číslo, the Greek AFM and AMKA and the Bulgarian EGN, read over one
    /// body. Every span names the rule that read it.
    Eu1cRecognizer,
    "eu_ids_1c",
    &RULES_1C
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_keeps_its_name_kind_and_score() {
        type Case<'a> = (&'a str, Box<dyn Recognizer>, &'a str, &'a str, f32, &'a str);
        let cases: [Case<'_>; 11] = [
            (
                "de_steuer_id",
                Box::new(DeSteuerIdRecognizer::new()),
                "Steuer-ID 26954371827",
                "26954371827",
                1.0,
                "26954371828",
            ),
            (
                "es_dni",
                Box::new(EsDniRecognizer::new()),
                "DNI 12345678Z",
                "12345678Z",
                1.0,
                "12345678A",
            ),
            (
                "it_codice_fiscale",
                Box::new(ItCodiceFiscaleRecognizer::new()),
                "codice fiscale ZMRPKC73R12H780Z",
                "ZMRPKC73R12H780Z",
                1.0,
                "zmrpkc73r12h780y",
            ),
            (
                "nl_bsn",
                Box::new(NlBsnRecognizer::new()),
                "BSN 456789236",
                "456789236",
                1.0,
                "456789237",
            ),
            (
                "be_national_number",
                Box::new(BeNationalNumberRecognizer::new()),
                "rijksregisternummer 91.07.22-406.21",
                "91.07.22-406.21",
                1.0,
                "91.07.22-406.22",
            ),
            (
                "pl_pesel",
                Box::new(PlPeselRecognizer::new()),
                "PESEL 92071314764",
                "92071314764",
                1.0,
                "92071314765",
            ),
            (
                "pt_nif",
                Box::new(PtNifRecognizer::new()),
                "NIF 234567899",
                "234567899",
                0.55,
                "234567899",
            ),
            (
                "at_sv_nr",
                Box::new(AtSvNrRecognizer::new()),
                "SV-Nr. 1230 150885",
                "1230 150885",
                1.0,
                "1231150885",
            ),
            (
                "ie_ppsn",
                Box::new(IePpsnRecognizer::new()),
                "PPSN: 1234567 T",
                "1234567 T",
                1.0,
                "1234567A",
            ),
            (
                "se_personnummer",
                Box::new(SePersonnummerRecognizer::new()),
                "personnummer 850709-3253",
                "850709-3253",
                1.0,
                "850709-3255",
            ),
            (
                "eu_ids_1c",
                Box::new(Eu1cRecognizer::new()),
                "CNP: 1850709401231",
                "1850709401231",
                1.0,
                "855709/1236",
            ),
        ];
        for (name, recognizer, text, value, score, invalid) in cases {
            assert_eq!(recognizer.name(), name);
            let spans = recognizer.analyze(text);
            let span = spans
                .iter()
                .find(|span| &text[span.start..span.end] == value)
                .unwrap_or_else(|| panic!("{name} missed {value} in {text:?}"));
            assert_eq!(
                (span.kind, span.score),
                (EntityKind::NationalId, score),
                "{name}"
            );
            assert!(
                recognizer.analyze(invalid).is_empty(),
                "{name} read the check-failing {invalid:?}"
            );
        }
    }
}
