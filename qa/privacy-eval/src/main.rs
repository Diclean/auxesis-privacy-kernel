//! Benchmark hook for the `qa/privacy-eval` JSONL corpus.
//!
//! Usage (from the repository root):
//!
//! * `cargo run -p privacy-eval --locked --release` prints the detection table:
//!   tier C and tier H recall on the held-out split, false positives on trap
//!   cases, p95 latency and, when the GLiNER feature and its model files are
//!   present, the Deep-detection rows. A missed bar prints `MISSED` and is
//!   never rounded up; an unavailable Deep row prints
//!   `NOT MEASURED`. Rows without a Standard/Deep qualifier use the detection
//!   level in force: Deep when the model is present, Standard otherwise.
//! * `cargo run -p privacy-eval --locked --release -- --legacy` prints the
//!   before/after table of the K04 runner (the pre-1e pipeline against the
//!   email-aware one).
//!
//! The table also prints a `Known contacts recall` row for the dictionary
//! recogniser over `qa/privacy-eval/known_contacts.jsonl`
//! (`{"id","dictionary","text","spans"}`, byte offsets). It has no bar; every
//! miss is printed, never hidden.
//!
//! ## What is scored (EVAL-NO-NAMES)
//!
//! Names are not hidden by design (2026-10-19): a gold name lowers no recall, a
//! detected name is no over-mask, neither reaches a bar or a precision. Tier C
//! is `EntityKind::is_prohibited` itself, and an empty tally prints
//! `n/a (n = 0)`, never `100 %`. `README.md` has the exact bar definitions.
//! A path argument is a `.jsonl` file or a directory of them. Every case is
//! `{"id","lang","text","spans":[{"type","start","end"}]}`.
//!
//! The held-out split is frozen in `qa/privacy-eval/heldout.txt` (one case id
//! per line, `#` comments allowed; it and `heldout-2.jsonl` live outside the
//! tree, see [`private_sets`]): the rule is FNV-1a 64 of the case id, held
//! out when `hash % 5 == 0` (~20 %), but the committed file is the source of
//! truth so the split never changes silently.
//!
//! ## Tier C (TIERC-HELDOUT-2)
//!
//! The Tier C bar is scored on `qa/privacy-eval/heldout-2.jsonl` (outside the
//! tree, in `$AUXESIS_EVAL_DIR`), a frozen set
//! of invented Tier C values whose line 1 is `# sha256: <hex>` of the rest of
//! the file; a mismatch refuses the run. It is scored through the production
//! gate (what leaves the Mac) in Private and Open, with the Registry beside it.
//! Only the owner's languages ([`IN_SCOPE_LANGS`](cases::IN_SCOPE_LANGS)) are
//! scored: the v1 split's other languages print on an unscored row, and the
//! old all-language row still prints with its bar, so no number disappears.
//!
//! ## Legacy runner
//!
//! With `--legacy`, the binary scores two registries over the same corpus:
//!
//! * **before** — `Registry::builder().with_all().without_email_layer()`, the
//!   pre-1e pipeline;
//! * **after** — `Registry::new()`, with the email-aware layer mounted.
//!
//! Scores are per case (P3-8). Recall and precision use the same-kind partial
//! overlap rule of the Python benchmark (`examples/ner_eval.rs`): the registry
//! merges an overlap into one union, so an exact-offset rule would score a
//! nested value as a miss even when its bytes are masked. *Mask coverage* is the
//! fraction of gold spans whose bytes are fully covered by the predicted union,
//! which is the metric the fail-toward-masking policy cares about. *Trap FP*
//! counts a predicted span whose exact value is a public term from the config
//! file.
//!
//! Set `AUX_EVAL_FP=1` to print every same-kind false positive with its value,
//! which is how an over-masking round is diagnosed.
//!
//! Timing is the wall time of the analyse loop, so the difference is the
//! layer's overhead. It reads only the paths it is given and never touches a
//! network.

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kernel_privacy::PublicTerms;

use crate::cases::read_cases;
use crate::legacy::run_legacy;
use crate::report::run_table;

mod cases;
mod classes;
mod deep;
mod gate;
mod heldout;
mod legacy;
mod private_sets;
mod report;
mod scoring;
mod table;
mod tier_c;
mod tiers;

// `private_sets` reaches the hash helper through the crate root.
pub(crate) use heldout::sha256_hex;

#[cfg(test)]
mod tests;

fn main() -> ExitCode {
    // Every binary target calls the shared guard before it reads anything
    // (`crates/kernel-core/tests/workspace_guard.rs`). This one reads only the
    // paths it is given, so the guard only verifies the home and refuses a
    // sandbox that points at the real one.
    if let Err(error) = kernel_core::ensure_sandbox_guard(None) {
        eprintln!("{error}");
        return ExitCode::from(2);
    }
    let mut legacy = false;
    let mut paths: Vec<PathBuf> = Vec::new();
    for arg in env::args().skip(1) {
        if arg == "--legacy" {
            legacy = true;
        } else {
            paths.push(PathBuf::from(arg));
        }
    }
    if paths.is_empty() {
        paths.push(PathBuf::from("qa/privacy-eval/cases"));
    }
    let cases = match read_cases(&paths) {
        Ok(cases) => cases,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    if cases.is_empty() {
        eprintln!("no cases");
        return ExitCode::from(2);
    }

    let public = Path::new("qa/privacy-eval/public-terms.json")
        .exists()
        .then(|| PublicTerms::from_path("qa/privacy-eval/public-terms.json").ok())
        .flatten()
        .unwrap_or_else(PublicTerms::builtin);

    if legacy {
        run_legacy(&cases, &public);
        return ExitCode::SUCCESS;
    }
    match run_table(&cases, &public) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
