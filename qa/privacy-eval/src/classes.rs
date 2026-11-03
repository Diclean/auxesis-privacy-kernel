//! Per-class reporting: the README table and the known-contacts row.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use kernel_core::privacy::{
    admit, Context, Decision, Destination, GrantPolicy, PathId, PrivacyMode,
};
use kernel_privacy::{EntityKind, Gate, NameDictionary, Recognizer};
use serde::Deserialize;

use crate::cases::{gold_spans, Case, Gold};
use crate::table::{print_row, rate_cell, NO_RATE};
use crate::tiers::is_name;

/// The rows of the per-class table. Every name [`report_class`] can return must
/// appear here or that class is measured and never shown.
pub(crate) const CLASS_ORDER: [&str; 13] = [
    "e-mail",
    "phone",
    "IBAN",
    "card",
    "ID",
    "business ID",
    "secret",
    "health",
    "special category",
    "address",
    "date of birth",
    "IP",
    "URL",
];

/// The README class of a kind, or `None` for a name.
///
/// Identity documents and company identifiers are separate rows on purpose: the
/// national ID kinds are prohibited, the SIREN/SIRET/VAT kinds are not, so a
/// shared row would understate the prohibited ones in Open. A name has no
/// class because it is not hidden, so there is nothing to report.
pub(crate) fn report_class(kind: EntityKind) -> Option<&'static str> {
    if is_name(kind) {
        return None;
    }
    Some(match kind {
        EntityKind::Email => "e-mail",
        EntityKind::Phone => "phone",
        EntityKind::Iban => "IBAN",
        EntityKind::CreditCard => "card",
        EntityKind::Secret => "secret",
        EntityKind::Address => "address",
        EntityKind::DateOfBirth => "date of birth",
        EntityKind::IpV4 => "IP",
        EntityKind::Url => "URL",
        EntityKind::Health => "health",
        EntityKind::Religion
        | EntityKind::SexualOrientation
        | EntityKind::Union
        | EntityKind::Ethnicity => "special category",
        EntityKind::FrSiren | EntityKind::FrSiret | EntityKind::FrVat => "business ID",
        EntityKind::FrNir
        | EntityKind::HuTaj
        | EntityKind::HuTaxId
        | EntityKind::ZaId
        | EntityKind::UkNino
        | EntityKind::PassportMrz
        | EntityKind::NationalId => "ID",
        EntityKind::Person | EntityKind::Organization => return None,
    })
}

/// One mode's measurement of the whole corpus.
#[derive(Default)]
pub(crate) struct ModeTable {
    /// Class -> `[hidden, n]`, the shape `Totals::per_kind` already uses.
    pub(crate) classes: BTreeMap<&'static str, [u64; 2]>,
    /// Classes this mode keeps in clear by design; their cell prints `n/a`.
    pub(crate) kept: BTreeSet<&'static str>,
    /// Texts holding no value of a scored class: a name does not make a text
    /// one, which is what keeps a name from reading as an over-mask.
    pub(crate) plain: u64,
    /// Those texts the gate changed anyway.
    pub(crate) over: u64,
    /// Texts the gate refused: never scored, and printed so one cannot hide.
    pub(crate) refused: u64,
}

/// The classes `policy` keeps in clear by design, so a 0 % against them is a
/// design statement and not a miss.
///
/// Read from the grant, never from the observed numbers. `Tokenised` (Private)
/// masks every class it detects, so it keeps none; `Passthrough` (Open) runs
/// the detectors and replaces only [`EntityKind::is_prohibited`] values with a
/// `[<class> removed]` marker, so it keeps every class outside that set.
/// Names are kept by both, and have no class here at all.
pub(crate) fn kept_by_design(policy: GrantPolicy) -> BTreeSet<&'static str> {
    if policy != GrantPolicy::Passthrough {
        return BTreeSet::new();
    }
    EntityKind::ALL
        .iter()
        .filter_map(|kind| report_class(*kind))
        .filter(|class| {
            !EntityKind::ALL
                .iter()
                .any(|kind| report_class(*kind) == Some(*class) && kind.is_prohibited())
        })
        .collect()
}

impl ModeTable {
    /// Record one value of `class`: `n` grows, and `hidden` when it is gone
    /// from what the gate issued.
    fn add(&mut self, class: &'static str, hidden: bool) {
        let tally = self.classes.entry(class).or_insert([0, 0]);
        tally[1] += 1;
        if hidden {
            tally[0] += 1;
        }
    }
}

/// Run every case through a production gate for `mode`, labelled `label`.
pub(crate) fn measure_mode(
    cases: &[Case],
    mode: PrivacyMode,
    label: &str,
) -> Result<ModeTable, String> {
    let context = Context {
        destination: Destination::Vendor("privacy-eval".into()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &context) else {
        return Err(format!("the A1 {label} grant was not admitted"));
    };
    let kept = kept_by_design(grant.policy());
    let mut gate = Gate::for_grant(&grant, [0x2Au8; 32]);
    let mut table = ModeTable::default();
    for case in cases {
        let (safe, _report) = match gate.text(&case.text) {
            Ok(issued) => issued,
            Err(error) => {
                table.refused += 1;
                eprintln!("privacy-eval: {label} refused {}: {error}", case.id);
                continue;
            }
        };
        let mut scored = 0u64;
        for gold in gold_spans(case) {
            let value = case.text.get(gold.start..gold.end).unwrap_or("");
            if let Some(class) = report_class(gold.kind) {
                scored += 1;
                table.add(class, !safe.as_str().contains(value));
            }
        }
        // Over-mask is what the reader sees: the issued text differs from the
        // input. A class the mode keeps in clear changes nothing, so it never
        // counts, whatever the detectors reported.
        if scored == 0 {
            table.plain += 1;
            if safe.as_str() != case.text {
                table.over += 1;
            }
        }
    }
    table.kept = kept;
    Ok(table)
}

/// The per-class Markdown block, a README pastes as is. Snapshot-tested: the
/// shape is a contract, so a column cannot move without a test failing.
pub(crate) fn class_table(private: &ModeTable, open: &ModeTable) -> String {
    // A class the mode never hides has nothing to report, so it reads as a
    // design statement; a class it does hide reads its rate, or n/a with no
    // value to read.
    let cell = |tally: Option<&[u64; 2]>, kept: bool| {
        if kept {
            "n/a (kept by design)".to_string()
        } else {
            tally.map_or_else(|| NO_RATE.to_string(), |t| rate_cell(t[0], t[1]))
        }
    };
    let mut out = String::from("| class | n | Private | Open |\n| --- | ---: | ---: | ---: |\n");
    for class in CLASS_ORDER {
        let n = private
            .classes
            .get(class)
            .or_else(|| open.classes.get(class))
            .map_or_else(|| NO_RATE.to_string(), |t| t[1].to_string());
        out.push_str(&format!(
            "| {class} | {n} | {} | {} |\n",
            cell(private.classes.get(class), private.kept.contains(class)),
            cell(open.classes.get(class), open.kept.contains(class)),
        ));
    }
    out.push_str(&format!(
        "over-mask on the no-PII texts: Private {}, Open {}\n",
        rate_cell(private.over, private.plain),
        rate_cell(open.over, open.plain)
    ));
    if private.refused + open.refused > 0 {
        out.push_str(&format!(
            "gate refusals, counted in neither: Private {}, Open {}\n",
            private.refused, open.refused
        ));
    }
    out
}

/// One known-contacts case: the dictionary a caller would seed, a text, and the
/// names the text must mask. Offsets are bytes.
#[derive(Deserialize)]
struct KnownCase {
    id: String,
    dictionary: Vec<String>,
    text: String,
    spans: Vec<Gold>,
}

/// Known-contacts recall: the share of gold names covered by one dictionary
/// match. Every miss is printed with its case id and value, never hidden.
fn known_contacts_recall(path: &Path) -> Result<(u64, u64), String> {
    let handle = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let (mut caught, mut total) = (0u64, 0u64);
    for (line_number, line) in BufReader::new(handle).lines().enumerate() {
        let line = line.map_err(|error| format!("{}: {error}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let case: KnownCase = serde_json::from_str(&line).map_err(|error| {
            format!(
                "{}:{}: malformed JSON: {error}",
                path.display(),
                line_number + 1
            )
        })?;
        let dictionary = NameDictionary::new(&case.dictionary)
            .map_err(|error| format!("{}: {error}", case.id))?;
        let found = dictionary.analyze(&case.text);
        for gold in &case.spans {
            total += 1;
            if found
                .iter()
                .any(|span| span.start <= gold.start && span.end >= gold.end)
            {
                caught += 1;
            } else {
                let value = case.text.get(gold.start..gold.end).unwrap_or("?");
                println!("  miss {}: {value:?} in {:?}", case.id, case.text);
            }
        }
    }
    Ok((caught, total))
}

/// The known-contacts row of the table. It has no bar: the slice reports the
/// recall and its misses, and a missing file prints `NOT MEASURED`.
pub(crate) fn print_known_contacts(path: &Path) {
    match known_contacts_recall(path) {
        Ok((caught, total)) => print_row(
            "Known contacts recall",
            &rate_cell(caught, total),
            "no bar",
            &format!("MEASURED {caught}/{total}"),
        ),
        Err(reason) => {
            eprintln!("privacy-eval: known contacts not measured: {reason}");
            print_row("Known contacts recall", "n/a", "no bar", "NOT MEASURED");
        }
    }
}
