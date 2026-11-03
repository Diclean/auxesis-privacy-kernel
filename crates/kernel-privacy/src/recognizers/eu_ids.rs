//! EU national and tax identifiers (EU-KERNEL-1a): Germany, Spain, Italy,
//! the Netherlands and Belgium; 1b: Poland, Portugal, Austria, Ireland, Sweden;
//! 1c: Romania, Czechia and Slovakia, Greece and Bulgaria, read over one body.
//!
//! Each rule follows the pattern of the French NIR and the UK National
//! Insurance number: a dedicated recogniser, a check digit that decides, and a
//! span that never carries the value itself. A value whose check digit holds
//! is hidden in Private mode and removed in Open mode, with a label and
//! without one; a value whose check digit fails stays in clear unless a label
//! names it, for a label is evidence and a typo is still personal data. The
//! value may carry spaces, dots, dashes or slashes between its groups, sit
//! glued to a prefix or a suffix, be in lower case, or hold full-width digits.
//! A run of separators that holds a line break is one separator, so a value
//! wrapped after a hyphen or a dot stays one value. A value that stands in
//! prose is not a fragment of an opaque token: the length of a token counts
//! its alphanumerics, never the punctuation of the value.
//! Every rule emits [`EntityKind::NationalId`], the kind the kernel removes in
//! Open mode, so a national identifier never leaves the Mac in any mode.

// The submodules are private on purpose: every item below is re-exported at
// this path, so `crate::recognizers::eu_ids::...` is exactly what it was
// before the split, and no new public path appears.
mod body;
mod checks;
mod cues;
mod ids_1a;
mod ids_1b;
mod ids_1c;
mod letters;
mod recognizers;
mod scan;

pub use recognizers::{
    AtSvNrRecognizer, BeNationalNumberRecognizer, DeSteuerIdRecognizer, EsDniRecognizer,
    Eu1cRecognizer, IePpsnRecognizer, ItCodiceFiscaleRecognizer, NlBsnRecognizer,
    PlPeselRecognizer, PtNifRecognizer, SePersonnummerRecognizer,
};

use crate::normalize::NormalizedText;
use crate::span::{EntityKind, Span};

use body::grouped_runs;
use cues::{
    AT_CUES, BE_CUES, BG_CUES, CZ_CUES, DE_CUES, ES_CUES, GR_AFM_CUES, GR_AMKA_CUES, IE_CUES,
    IT_CUES, NL_CUES, PL_CUES, PT_CUES, RO_CUES, SE_CUES,
};
use ids_1a::{be_candidates, de_candidates, es_candidates, it_candidates, nl_candidates};
use ids_1b::{at_candidates, ie_candidates, pl_candidates, pt_candidates, se_candidates};
use ids_1c::{bg_candidates, cz_candidates, gr_afm_candidates, gr_amka_candidates, ro_candidates};
use scan::{has_cue, in_opaque_token};

/// The kind every rule here emits: a national identifier.
const KIND: EntityKind = EntityKind::NationalId;

/// The length of the Italian codice fiscale, which never hides in a hash.
const IT_LENGTH: usize = 16;

/// The score of a value whose check digit holds and a label names it.
const CUED_VALID_SCORE: f32 = 1.0;

/// The score of a value whose check digit holds and no label names it.
const BARE_SCORE: f32 = 0.6;

/// The score of a value a label names whose check digit fails: a typo in a
/// real document is still personal data, so it stays hidden.
const CUED_SCORE: f32 = 0.55;

/// The verdict of a check digit.
type Check = fn(&str) -> bool;

/// Whether a run is printed in the shape a value is issued in.
type Shape = fn(&str) -> bool;

/// The label words of one rule, each a sequence of words (`codice fiscale`).
type Cue = &'static [&'static str];

/// A candidate: its byte range and whether its check digit holds.
struct Candidate {
    start: usize,
    end: usize,
    ok: bool,
}

impl Candidate {
    /// A candidate over `start..end` whose check digit holds or not.
    fn new(start: usize, end: usize, ok: bool) -> Self {
        Self { start, end, ok }
    }
}

/// One country rule: the name, the label words and how candidates are found.
struct Rule(
    &'static str,
    &'static [Cue],
    fn(&Body<'_>) -> Vec<Candidate>,
);

/// Every country rule, in run order.
static RULES: [Rule; 10] = [
    Rule("de_steuer_id", DE_CUES, de_candidates),
    Rule("es_dni", ES_CUES, es_candidates),
    Rule("it_codice_fiscale", IT_CUES, it_candidates),
    Rule("nl_bsn", NL_CUES, nl_candidates),
    Rule("be_national_number", BE_CUES, be_candidates),
    Rule("pl_pesel", PL_CUES, pl_candidates),
    Rule("pt_nif", PT_CUES, pt_candidates),
    Rule("at_sv_nr", AT_CUES, at_candidates),
    Rule("ie_ppsn", IE_CUES, ie_candidates),
    Rule("se_personnummer", SE_CUES, se_candidates),
];

/// The rules of EU-KERNEL-1c: Romania, Czechia and Slovakia, Greece and
/// Bulgaria. One recogniser reads them over one body, so the text is grouped
/// into runs once for the five, not once each.
static RULES_1C: [Rule; 5] = [
    Rule("ro_cnp", RO_CUES, ro_candidates),
    Rule("cz_sk_rodne_cislo", CZ_CUES, cz_candidates),
    Rule("gr_afm", GR_AFM_CUES, gr_afm_candidates),
    Rule("gr_amka", GR_AMKA_CUES, gr_amka_candidates),
    Rule("bg_egn", BG_CUES, bg_candidates),
];

/// Every value of `rules` in `text`, with the score its label and its check
/// digit earn. The rules read one body.
fn spans_for(rules: &[Rule], text: &str) -> Vec<Span> {
    let normalized = NormalizedText::new(text, false);
    let body = Body::new(normalized.text(), text, &normalized);
    let mut spans = Vec::new();
    for rule in rules {
        spans.extend(
            (rule.2)(&body)
                .into_iter()
                .filter(|candidate| !in_opaque_token(body.text, candidate))
                .filter_map(|candidate| {
                    let cued = has_cue(body.text, candidate.start, rule.1);
                    let score = match (candidate.ok, cued) {
                        (true, true) => CUED_VALID_SCORE,
                        (true, false) => BARE_SCORE,
                        (false, true) => CUED_SCORE,
                        (false, false) => return None,
                    };
                    normalized
                        .to_original(candidate.start, candidate.end)
                        .map(|(start, end)| Span::new(KIND, start, end, score, rule.0))
                }),
        );
    }
    spans
}

/// What the rules read: the normalised body of the text, its digit runs, and
/// the original text, to see the line breaks the normaliser folded.
struct Body<'a> {
    /// The normalised text the rules read.
    text: &'a str,
    /// The original text the body came from.
    original: &'a str,
    /// The view that maps the body back to the original.
    view: &'a NormalizedText,
    /// The digit runs of the body, with the runs a line break separates joined
    /// into one run more.
    runs: Vec<(usize, usize)>,
}

impl<'a> Body<'a> {
    /// The body of the text: its digit runs, with the runs a line break
    /// separates joined into one run more.
    fn new(text: &'a str, original: &'a str, view: &'a NormalizedText) -> Self {
        let runs = grouped_runs(text, original, view);
        Self {
            text,
            original,
            view,
            runs,
        }
    }

    /// Whether the run of separators `from..to` of the body holds a line
    /// break: the original bytes of the run hold one.
    ///
    /// The normaliser folds a break to a space, so the body alone cannot tell
    /// a folded break from a space: only the original bytes can.
    fn holds_break(&self, from: usize, to: usize) -> bool {
        let Some((start, end)) = self.view.to_original(from, to) else {
            return false;
        };
        self.original
            .get(start..end)
            .is_some_and(|bytes| bytes.contains(['\n', '\r']))
    }
}
