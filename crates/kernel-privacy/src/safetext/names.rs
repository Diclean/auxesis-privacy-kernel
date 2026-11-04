//! The optional second name pass: the spotter trait, its bounded worker, and the
//! two-pass detector that adds only names to pass 1.

use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, OnceLock};

use kernel_core::sync::lock_recover;

use super::detector::Detector;
use super::report::DetectError;
use crate::recognizer::span_is_well_formed;
use crate::span::{EntityKind, Span};

/// The second pass of a private gate (first round the dictionary, second
/// round with what stays): a local model that finds the
/// person, organisation and address names the patterns and the dictionary do
/// not know. It only ever adds spans; it can never remove one.
pub trait NameSpotter: Send + Sync {
    /// Name spans in `text`, or an error. The caller falls back to pass 1 alone
    /// on an error; an implementation must not put `text` in the error.
    fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError>;
}

static NAME_SPOTTER: OnceLock<Arc<dyn NameSpotter>> = OnceLock::new();

/// Install the process-wide second pass; the first install wins. Tokenising
/// gates built afterwards run it; open mode never does.
pub fn install_name_spotter(spotter: Arc<dyn NameSpotter>) -> bool {
    NAME_SPOTTER.set(spotter).is_ok()
}

/// Whether a second pass is installed in this process.
pub fn name_spotter_installed() -> bool {
    NAME_SPOTTER.get().is_some()
}

/// Directory under `$AUXESIS_HOME/models/` that holds the second-pass model.
pub const LOCAL_MODEL_DIR: &str = "gliner2-pii";

/// `crate::ner::install_local_model` when this build has the `ner-gliner`
/// feature; without it there is no second pass and this returns `false`.
pub fn install_local_name_model(root: &std::path::Path, model_dir: &std::path::Path) -> bool {
    #[cfg(feature = "ner-gliner")]
    {
        crate::ner::install_local_model(root, model_dir)
    }
    #[cfg(not(feature = "ner-gliner"))]
    {
        let _ = (root, model_dir);
        false
    }
}

/// A [`NameSpotter`] run on one dedicated worker thread, with an input cap and a
/// deadline, so a slow or huge text can never stall a turn.
///
/// A text over `max_bytes` is not read at all (checked before the inner spotter
/// sees it). The inner spotter runs on the worker; if it has not answered within
/// `deadline` the call returns an error and the gate keeps pass 1. While the
/// worker is still busy with a late text, later texts skip the second pass
/// instead of queueing behind it. Each cause logs one line, never the text.
pub struct BoundedSpotter {
    inner: Arc<dyn NameSpotter>,
    max_bytes: usize,
    deadline: std::time::Duration,
    busy: Arc<std::sync::atomic::AtomicBool>,
    worker: std::sync::Mutex<Option<std::sync::mpsc::Sender<SpotJob>>>,
    logged: [std::sync::atomic::AtomicBool; 3],
}

type SpotJob = (
    String,
    std::sync::mpsc::SyncSender<Result<Vec<Span>, DetectError>>,
);

impl BoundedSpotter {
    /// `inner` behind a `max_bytes` input cap and a `deadline` per text.
    pub fn new(
        inner: Arc<dyn NameSpotter>,
        max_bytes: usize,
        deadline: std::time::Duration,
    ) -> Self {
        Self {
            inner,
            max_bytes,
            deadline,
            busy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            worker: std::sync::Mutex::new(None),
            logged: Default::default(),
        }
    }

    fn skip(&self, cause: usize, line: &str) -> Result<Vec<Span>, DetectError> {
        if !self.logged[cause].swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("auxesis: private mode: {line}; that text is checked by pass 1 only");
        }
        Err(DetectError::Names)
    }

    fn sender(&self) -> Option<std::sync::mpsc::Sender<SpotJob>> {
        let mut worker = lock_recover(&self.worker);
        if worker.is_none() {
            let (tx, rx) = std::sync::mpsc::channel::<SpotJob>();
            let inner = Arc::clone(&self.inner);
            let busy = Arc::clone(&self.busy);
            std::thread::Builder::new()
                .name("auxesis-name-spotter".into())
                .spawn(move || {
                    for (text, reply) in rx {
                        let result = panic::catch_unwind(AssertUnwindSafe(|| inner.spot(&text)))
                            .unwrap_or(Err(DetectError::Panicked));
                        busy.store(false, std::sync::atomic::Ordering::Release);
                        let _ = reply.send(result);
                    }
                })
                .ok()?;
            *worker = Some(tx);
        }
        worker.clone()
    }
}

impl NameSpotter for BoundedSpotter {
    fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        use std::sync::atomic::Ordering;
        if text.len() > self.max_bytes {
            return self.skip(0, "a text is too long for the local name model");
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return self.skip(1, "the local name model is still busy with an earlier text");
        }
        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        let sent = self
            .sender()
            .is_some_and(|tx| tx.send((text.to_string(), reply)).is_ok());
        if !sent {
            self.busy.store(false, Ordering::Release);
            *lock_recover(&self.worker) = None;
            return self.skip(1, "the local name model worker is not running");
        }
        match answer.recv_timeout(self.deadline) {
            Ok(result) => result,
            Err(_) => self.skip(2, "the local name model took too long"),
        }
    }
}

/// Pass 1 (`first`) plus the name spotter on the same text. Pass 1 wins every
/// overlap. When the spotter errors or panics the text keeps its pass-1 spans
/// and the call reports that names were not covered by the spotter: the turn
/// never blocks on the model.
pub struct TwoPassDetector {
    first: Arc<dyn Detector>,
    spotter: Arc<dyn NameSpotter>,
}

impl TwoPassDetector {
    /// Pass 1 `first`, pass 2 `spotter`.
    pub fn new(first: Arc<dyn Detector>, spotter: Arc<dyn NameSpotter>) -> Self {
        Self { first, spotter }
    }
}

impl Detector for TwoPassDetector {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(self.detect_covered(text)?.0)
    }

    fn detect_covered(&self, text: &str) -> Result<(Vec<Span>, bool), DetectError> {
        let (mut spans, first_covered) = self.first.detect_covered(text)?;
        let spotted = panic::catch_unwind(AssertUnwindSafe(|| self.spotter.spot(text)));
        let Ok(Ok(found)) = spotted else {
            return Ok((spans, first_covered));
        };
        let extra: Vec<Span> = found
            .into_iter()
            .filter(|span| {
                matches!(
                    span.kind,
                    EntityKind::Person | EntityKind::Organization | EntityKind::Address
                ) && span_is_well_formed(text, span)
                    && !(span.kind != EntityKind::Address
                        && model_function_word(&text[span.start..span.end])
                        && !reads_as_name(text, span))
                    && !spans.iter().any(|kept| kept.overlaps(span))
            })
            .collect();
        spans.extend(extra);
        spans.sort_by_key(|span| (span.start, span.end));
        Ok((spans, true))
    }

    fn detect_patterns(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.first.detect_patterns(text)
    }

    fn checks_names(&self) -> bool {
        self.first.checks_names()
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.first.residue(text)
    }
}

/// Words the name model tags as a person or an organisation on their own at
/// its low name floor ("Who wrote to me last?" lost its `Who`), beyond
/// the closed function words. These are real given names too, so only a
/// model span of the word alone is dropped: "May Smith" is still a name, and
/// the owner's contacts (pass 1) are never filtered this way.
const MODEL_NOT_NAMES: &str = "why how i can may will june";

/// Whether a model name span is one function word and nothing else.
fn model_function_word(value: &str) -> bool {
    let word =
        crate::contacts::fold::folded_text(value.trim_matches(|ch: char| !ch.is_alphanumeric()));
    !word.contains(char::is_whitespace)
        && (crate::contacts::stopwords::is_closed_word(&word)
            || MODEL_NOT_NAMES
                .split_whitespace()
                .any(|listed| listed == word))
}

/// Given names that are also words, and what greets or signs a name.
const WORD_NAMES: &str = "can may will june";
const GREETINGS: &str = "hi hey hello dear thanks cheers";

/// Whether context makes a [`WORD_NAMES`] span a name: a capitalised surname
/// follows (`May Smith`), or a greeting or a signature dash comes before it
/// (`Hi June,`, `— Will`).
fn reads_as_name(text: &str, span: &Span) -> bool {
    let folded = |word: &str| crate::contacts::fold::folded_text(word);
    let listed = |list: &str, word: &str| list.split_whitespace().any(|w| w == folded(word));
    if !listed(WORD_NAMES, text[span.start..span.end].trim()) {
        return false;
    }
    let next = text[span.end..]
        .trim_start_matches(' ')
        .split(|ch: char| !ch.is_alphanumeric())
        .next()
        .unwrap_or_default();
    let before = text[..span.start].trim_end_matches([' ', ',']);
    (next.starts_with(char::is_uppercase) && !model_function_word(next))
        || before.ends_with(['—', '–', '-'])
        || before
            .rsplit(|ch: char| !ch.is_alphanumeric())
            .next()
            .is_some_and(|word| listed(GREETINGS, word))
}
