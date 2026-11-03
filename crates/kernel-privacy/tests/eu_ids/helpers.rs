//! Helpers shared by the EU identifier test modules: the rules of the
//! work order, the spans they read and the assertion every test makes.

use kernel_privacy::recognizers::eu_ids::{
    AtSvNrRecognizer, BeNationalNumberRecognizer, DeSteuerIdRecognizer, EsDniRecognizer,
    Eu1cRecognizer, IePpsnRecognizer, ItCodiceFiscaleRecognizer, NlBsnRecognizer,
    PlPeselRecognizer, PtNifRecognizer, SePersonnummerRecognizer,
};
use kernel_privacy::{Recognizer, Span};

#[allow(dead_code)]
mod cases {
    include!("../data/norm1_cases.rs");
}
pub(crate) use cases::{covered, issue, masked, wide, MODES};

/// Every rule of the work order.
pub(crate) fn rules() -> Vec<Box<dyn Recognizer>> {
    vec![
        Box::new(DeSteuerIdRecognizer::new()),
        Box::new(EsDniRecognizer::new()),
        Box::new(ItCodiceFiscaleRecognizer::new()),
        Box::new(NlBsnRecognizer::new()),
        Box::new(BeNationalNumberRecognizer::new()),
        Box::new(PlPeselRecognizer::new()),
        Box::new(PtNifRecognizer::new()),
        Box::new(AtSvNrRecognizer::new()),
        Box::new(IePpsnRecognizer::new()),
        Box::new(SePersonnummerRecognizer::new()),
        Box::new(Eu1cRecognizer::new()),
    ]
}

/// The spans the rule of a class reads in `text`: every span names its rule.
pub(crate) fn spans_of(class: &str, text: &str) -> Vec<Span> {
    rules()
        .iter()
        .flat_map(|rule| rule.analyze(text))
        .filter(|span| span.recognizer == class)
        .collect()
}

/// The value never reaches the cloud: it is hidden in Private mode and
/// removed in Open mode, and the gate masks every byte of it.
pub(crate) fn assert_hidden_in_both_modes(value: &str) {
    for mode in MODES {
        let (output, _) = issue(mode, value).expect("the gate issues the text");
        assert!(!output.contains(value), "{mode:?} kept {value:?}");
        let ranges = masked(mode, value).expect("the gate issues the text");
        assert!(
            covered(&ranges, 0, value.len()),
            "{mode:?} did not cover {value:?}"
        );
    }
}

/// The value inside the text never reaches the cloud: it is hidden in Private
/// mode and removed in Open mode, and the gate masks every byte of it. The
/// prose around it stays in clear.
pub(crate) fn assert_value_hidden_in_both_modes(text: &str, value: &str) {
    let start = text.find(value).expect("the value is in the text");
    let end = start + value.len();
    for mode in MODES {
        let (output, _) = issue(mode, text).expect("the gate issues the text");
        assert!(!output.contains(value), "{mode:?} kept {value:?}");
        let ranges = masked(mode, text).expect("the gate issues the text");
        assert!(
            covered(&ranges, start, end),
            "{mode:?} did not cover {value:?}"
        );
    }
}
