//! The second name pass, its bounded worker, and the Deep model stack.

use super::*;
use crate::anonymize::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
use crate::known_names::NameDictionary;
use crate::recognizer::resolve_overlaps;
use crate::safetext::prohibited::consolidate_mask_spans;
use crate::span::{EntityKind, Span};
use kernel_core::privacy::Grant;
use std::sync::Arc;

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
#[cfg(feature = "ner-gliner")]
const KEY: [u8; 32] = [9; 32];

const TEXT: &str = "Please call Camille Exemple at Exemple Conseil SARL";

fn private_grant() -> Grant {
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, PrivacyMode::Private, &ctx) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[cfg(feature = "ner-gliner")]
fn grant(mode: PrivacyMode) -> Grant {
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, mode, &ctx) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow, got {other:?}"),
    }
}

/// Finds each needle as a span of the given kind, like a model would.
struct Finds(Vec<(&'static str, EntityKind)>);

impl NameSpotter for Finds {
    fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(self
            .0
            .iter()
            .filter_map(|(needle, kind)| {
                let start = text.find(needle)?;
                Some(Span::new(*kind, start, start + needle.len(), 0.9, "fake"))
            })
            .collect())
    }
}

struct Fails;

impl NameSpotter for Fails {
    fn spot(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
        Err(DetectError::Names)
    }
}

struct Panics;

impl NameSpotter for Panics {
    fn spot(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
        panic!("the model blew up");
    }
}

fn gate_with(spotter: impl NameSpotter + 'static) -> Gate {
    let detector = TwoPassDetector::new(Arc::new(StandardDetector::new()), Arc::new(spotter));
    Gate::for_tests(&private_grant(), [9u8; 32], Arc::new(detector))
}

#[test]
fn mask_consolidation_keeps_pre_250_ordinary_overlaps() {
    let cases = [
        vec![
            Span::new(EntityKind::Person, 0, 12, 0.9, "fake"),
            Span::new(EntityKind::Health, 5, 12, 0.95, "fake"),
        ],
        vec![
            Span::new(EntityKind::Person, 0, 12, 0.9, "fake"),
            Span::new(EntityKind::Organization, 5, 14, 0.9, "fake"),
        ],
        vec![
            Span::new(EntityKind::Person, 0, 20, 0.8, "fake"),
            Span::new(EntityKind::Address, 4, 16, 0.9, "fake"),
            Span::new(EntityKind::Organization, 7, 12, 0.7, "fake"),
        ],
        vec![
            Span::new(EntityKind::Person, 0, 8, 0.9, "fake"),
            Span::new(EntityKind::Organization, 0, 8, 0.9, "fake"),
        ],
    ];
    for spans in cases {
        let expected: Vec<_> = resolve_overlaps(spans.clone())
            .into_iter()
            .filter(|span| !span.kind.is_prohibited())
            .collect();
        let actual: Vec<_> = consolidate_mask_spans(spans)
            .into_iter()
            .filter(|span| !span.kind.is_prohibited())
            .collect();
        assert_eq!(actual, expected);
    }

    for input in 0..2_000 {
        let shift = input % 7;
        let score = [0.6, 0.7, 0.8, 0.9][input % 4];
        let spans = vec![
            Span::new(EntityKind::Person, shift, shift + 12, score, "fake-deep"),
            Span::new(
                EntityKind::Organization,
                shift + input % 3,
                shift + 10,
                score,
                "fake-deep",
            ),
            Span::new(
                EntityKind::Address,
                shift + 4,
                shift + 15,
                0.85,
                "fake-deep",
            ),
            Span::new(EntityKind::Health, shift + 2, shift + 13, 0.95, "fake-deep"),
            Span::new(
                EntityKind::NationalId,
                shift + 8,
                shift + 11,
                0.95,
                "fake-deep",
            ),
        ];
        let expected: Vec<_> = resolve_overlaps(spans.clone())
            .into_iter()
            .filter(|span| !span.kind.is_prohibited())
            .collect();
        let actual: Vec<_> = consolidate_mask_spans(spans)
            .into_iter()
            .filter(|span| !span.kind.is_prohibited())
            .collect();
        assert_eq!(actual, expected, "fake-Deep input {input}");
    }
}

fn rehydrate(masked: &str, minted: &[(String, String)]) -> String {
    minted
        .iter()
        .fold(masked.to_string(), |text, (token, value)| {
            text.replace(
                &format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}"),
                value,
            )
        })
}

#[test]
fn spotted_names_are_tokenised_and_rehydrate_exactly() {
    let mut gate = gate_with(Finds(vec![
        ("Camille Exemple", EntityKind::Person),
        ("Exemple Conseil SARL", EntityKind::Organization),
    ]));
    let (safe, report) = gate.text(TEXT).unwrap();
    assert!(!safe.as_str().contains("Camille"), "{}", safe.as_str());
    assert!(!safe.as_str().contains("Conseil"), "{}", safe.as_str());
    assert_eq!(report.count(EntityKind::Person), 1);
    assert_eq!(report.count(EntityKind::Organization), 1);
    assert!(safe.names_checked());
    assert_eq!(rehydrate(safe.as_str(), &gate.take_minted()), TEXT);
}

#[test]
fn a_function_word_the_model_calls_a_name_stays_in_clear() {
    // TOK-FP: at its low name floor the model tagged "Who" in "Who wrote to
    // me last?" as a person, so the question reached the agents broken.
    let words = ["Who", "What", "You", "When", "Can", "May", "Will", "June"];
    let found = words.iter().map(|word| (*word, EntityKind::Person));
    let mut gate = gate_with(Finds(
        found.chain([("May Smith", EntityKind::Person)]).collect(),
    ));
    for text in [
        "Who wrote to me last?",
        "What is on today?",
        "You there?",
        "When can I call? Will June work?",
    ] {
        let (safe, report) = gate.text(text).unwrap();
        assert_eq!(safe.as_str(), text, "{report}");
    }
    let (safe, _) = gate.text("Ask May Smith").unwrap();
    assert!(!safe.as_str().contains("Smith"), "{}", safe.as_str());
}

#[test]
fn a_word_name_stays_a_name_where_context_says_so() {
    let words = ["Can", "May", "Will", "June"];
    let mut gate = gate_with(Finds(
        words
            .iter()
            .map(|word| (*word, EntityKind::Person))
            .collect(),
    ));
    for (text, name) in [
        ("June Carter called", "June"),
        ("Hi June, see you soon", "June"),
        ("Thanks for that.\n— Will", "Will"),
        ("Dear May,", "May"),
    ] {
        let (safe, _) = gate.text(text).unwrap();
        assert!(!safe.as_str().contains(name), "{}", safe.as_str());
    }
}

#[test]
fn no_text_after_a_match_is_ever_removed() {
    let path = "/tmp/zq/plokij415_5uhyt7gtr13svxm0000gn/T/tmp.mTRfRr6UCj";
    let text = format!("workspace {path}\nProposed command: ls {path} now");
    let mut gate = gate_with(Finds(Vec::new()));
    assert_eq!(gate.text(&text).unwrap().0.as_str(), text);
    let (safe, _) = gate
        .text("IBAN FR76 3000 6000 0112 3456 7890 189 Proposed command")
        .unwrap();
    let rest = safe.as_str().split_once('⟧').map(|(_, rest)| rest);
    assert_eq!(rest, Some(" Proposed command"), "{}", safe.as_str());
}

#[test]
fn a_failing_or_panicking_second_pass_falls_back_to_pass_one() {
    let text = "Call +33612345678 and ask for Camille Exemple";
    let mut gates = [gate_with(Fails), gate_with(Panics)];
    for gate in &mut gates {
        let (safe, _) = gate.text(text).expect("the turn is never blocked");
        assert!(!safe.as_str().contains("+33612345678"));
        assert!(safe.as_str().contains("Camille Exemple"), "pass 1 only");
        assert!(!safe.names_checked(), "names were not covered");
    }
}

#[test]
fn pass_one_wins_overlaps_and_the_second_pass_adds_only_names() {
    let mut gate = gate_with(Finds(vec![
        ("camille@exemple.fr", EntityKind::Person),
        ("Please", EntityKind::Phone),
    ]));
    let (safe, report) = gate.text("Please write camille@exemple.fr").unwrap();
    assert_eq!(report.count(EntityKind::Email), 1);
    assert_eq!(report.count(EntityKind::Person), 0);
    assert_eq!(report.count(EntityKind::Phone), 0);
    assert!(safe.as_str().contains("Please"));
}

#[test]
fn an_absent_model_mounts_no_second_pass() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!install_local_name_model(dir.path(), dir.path()));
    assert!(!name_spotter_installed());
    let mut gate = Gate::for_grant(&private_grant(), [9u8; 32]);
    let (safe, _) = gate.text("Call +33612345678 now").unwrap();
    assert!(!safe.as_str().contains("+33612345678"));
    assert!(!safe.names_checked());
}

/// Sleeps on its first text only, then answers at once.
struct Slow(std::time::Duration, std::sync::atomic::AtomicBool);

impl NameSpotter for Slow {
    fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        if !self.1.swap(true, std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(self.0);
        }
        Finds(vec![("Camille Exemple", EntityKind::Person)]).spot(text)
    }
}

fn bounded(inner: impl NameSpotter + 'static, max: usize, ms: u64) -> Arc<BoundedSpotter> {
    Arc::new(BoundedSpotter::new(
        Arc::new(inner),
        max,
        std::time::Duration::from_millis(ms),
    ))
}

struct Shared(Arc<BoundedSpotter>);

impl NameSpotter for Shared {
    fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.0.spot(text)
    }
}

#[test]
fn a_slow_second_pass_times_out_and_later_texts_skip_it_instead_of_queueing() {
    let text = "Call +33612345678 and ask for Camille Exemple";
    let slow = bounded(
        Slow(std::time::Duration::from_millis(700), false.into()),
        1024,
        100,
    );
    let mut gate = gate_with(Shared(Arc::clone(&slow)));
    let started = std::time::Instant::now();
    let (safe, _) = gate.text(text).expect("the turn is never blocked");
    assert!(started.elapsed() < std::time::Duration::from_millis(600));
    assert!(!safe.as_str().contains("+33612345678"));
    assert!(safe.as_str().contains("Camille Exemple"), "pass 1 only");
    assert!(!safe.names_checked());
    // The worker is still sleeping: the next text skips pass 2 at once.
    let started = std::time::Instant::now();
    let (safe, _) = gate.text(text).unwrap();
    assert!(started.elapsed() < std::time::Duration::from_millis(300));
    assert!(!safe.names_checked());
    // Once the worker is free again the second pass answers.
    std::thread::sleep(std::time::Duration::from_millis(800));
    let spans = slow.spot(text).expect("the worker recovered");
    assert_eq!(spans.len(), 1);
}

#[test]
fn an_oversize_text_never_reaches_the_second_pass() {
    let spotter = bounded(Finds(vec![("Camille", EntityKind::Person)]), 64, 2000);
    let mut gate = gate_with(Shared(spotter));
    let text = format!("Call +33612345678 for Camille Exemple {}", "x ".repeat(64));
    let (safe, _) = gate.text(&text).expect("the turn is never blocked");
    assert!(!safe.as_str().contains("+33612345678"));
    assert!(safe.as_str().contains("Camille Exemple"), "pass 1 only");
    assert!(!safe.names_checked());
}

#[test]
fn a_text_under_the_cap_in_time_is_spotted_on_the_worker() {
    let spotter = bounded(
        Finds(vec![("Camille Exemple", EntityKind::Person)]),
        1024,
        2000,
    );
    let mut gate = gate_with(Shared(spotter));
    let (safe, _) = gate.text(TEXT).unwrap();
    assert!(!safe.as_str().contains("Camille"));
    assert!(safe.names_checked());
}

#[cfg(feature = "ner-gliner")]
struct FixedDeep(Result<Vec<Span>, DetectError>);

#[cfg(feature = "ner-gliner")]
impl Detector for FixedDeep {
    fn detect(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
        self.0.clone()
    }
}

#[cfg(feature = "ner-gliner")]
struct GeneratedDeep;

#[cfg(feature = "ner-gliner")]
impl Detector for GeneratedDeep {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        let start = text.find("ordinarytag").ok_or(DetectError::Names)?;
        // Deliberately adversarial: a full health span, a short equal-score
        // ID at its start, and a non-prohibited label over the same bytes.
        Ok(vec![
            Span::new(EntityKind::Health, start, text.len(), 0.9, "fake"),
            Span::new(EntityKind::NationalId, start, start + 3, 0.9, "fake"),
            Span::new(EntityKind::Person, start, text.len(), 1.0, "fake"),
        ])
    }
}

#[cfg(feature = "ner-gliner")]
struct BlockedDeep {
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    finished: std::sync::mpsc::SyncSender<()>,
}

#[cfg(feature = "ner-gliner")]
static DEEP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(feature = "ner-gliner")]
impl Detector for BlockedDeep {
    fn detect(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
        self.release
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| DetectError::Names)?;
        let _ = self.finished.send(());
        Ok(Vec::new())
    }
}

#[cfg(feature = "ner-gliner")]
fn deep_gate(mode: PrivacyMode, spans: Result<Vec<Span>, DetectError>) -> Gate {
    Gate::for_grant_with_deep_detector(
        &grant(mode),
        KEY,
        Arc::new(NameDictionary::new(std::iter::empty::<&str>()).expect("empty dictionary")),
        Arc::new(FixedDeep(spans)),
    )
}

#[cfg(feature = "ner-gliner")]
#[test]
fn deep_adds_only_prohibited_tier_c_and_standard_wins_overlap() {
    let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let text = "Asterian health and +33612345678";
    let health = Span::new(EntityKind::Health, 16, 19, 1.0, "fake");
    let person = Span::new(EntityKind::Person, 0, 8, 1.0, "fake");
    let phone_overlap = Span::new(EntityKind::Secret, 22, text.len(), 1.0, "fake");
    let mut deep = deep_gate(PrivacyMode::Open, Ok(vec![health, person, phone_overlap]));
    let (safe, _) = deep.text(text).unwrap();
    assert!(safe.as_str().contains("[health removed]"));
    assert!(safe.as_str().contains("Asterian"));
    assert!(safe.as_str().contains("[secret removed]"));
    let mut names_only = deep_gate(
        PrivacyMode::Open,
        Ok(vec![Span::new(EntityKind::Person, 0, 8, 1.0, "fake")]),
    );
    assert_eq!(names_only.text("Asterian").unwrap().0.as_str(), "Asterian");
}

#[cfg(feature = "ner-gliner")]
#[test]
fn deep_non_prohibited_overlaps_cannot_suppress_health_or_secret() {
    let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let text = "QZXHEALTHTOKEN / QZXSECRETTOKEN";
    let health = text.find("QZXHEALTHTOKEN").unwrap();
    let secret = text.find("QZXSECRETTOKEN").unwrap();
    let spans = vec![
        Span::new(EntityKind::Person, health, health + 14, 0.99, "fake"),
        Span::new(EntityKind::Health, health, health + 14, 0.6, "fake"),
        Span::new(EntityKind::Address, secret, secret + 14, 0.99, "fake"),
        Span::new(EntityKind::Secret, secret, secret + 14, 0.6, "fake"),
    ];
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        let mut gate = deep_gate(mode, Ok(spans.clone()));
        let safe = gate.text(text).unwrap().0;
        assert!(!safe.as_str().contains("QZXHEALTHTOKEN"));
        assert!(!safe.as_str().contains("QZXSECRETTOKEN"));
    }
}

#[cfg(feature = "ner-gliner")]
#[test]
fn deep_prohibited_overlaps_are_unioned_in_both_modes() {
    let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let text = "QZX health value and secret tail marker";
    let health = Span::new(EntityKind::Health, 0, 27, 0.9, "fake");
    let id = Span::new(EntityKind::NationalId, 0, 3, 0.9, "fake");
    let secret = Span::new(EntityKind::Secret, 20, 39, 0.8, "fake");
    let short_health = Span::new(EntityKind::Health, 24, 28, 0.8, "fake");
    let spans = vec![health, id, secret, short_health];
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        let mut gate = deep_gate(mode, Ok(spans.clone()));
        let output = gate.text(text).unwrap().0;
        assert!(
            !output.as_str().contains("QZX health"),
            "{mode:?}: {}",
            output.as_str()
        );
        assert!(
            !output.as_str().contains("secret tail"),
            "{mode:?}: {}",
            output.as_str()
        );
    }
}

#[cfg(feature = "ner-gliner")]
#[test]
fn deep_failure_and_empty_output_match_standard_and_private_tokens_repeat() {
    let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let text = "Ordinary prose; Asterian";
    let names = Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap());
    let mut standard =
        Gate::for_grant_with_dictionary(&grant(PrivacyMode::Private), KEY, Arc::clone(&names));
    let mut failed = deep_gate(PrivacyMode::Private, Err(DetectError::Names));
    let mut empty = deep_gate(PrivacyMode::Private, Ok(Vec::new()));
    let base = standard.text(text).unwrap().0.as_str().to_owned();
    assert_eq!(failed.text(text).unwrap().0.as_str(), base);
    assert_eq!(
        empty.text("No private values here.").unwrap().0.as_str(),
        "No private values here."
    );
    let health = Span::new(EntityKind::Health, 17, text.len(), 1.0, "fake");
    let mut deep = deep_gate(PrivacyMode::Private, Ok(vec![health]));
    let first = deep.text(text).unwrap().0.as_str().to_owned();
    let second = deep.text(text).unwrap().0.as_str().to_owned();
    assert_eq!(first, second);
    assert_ne!(first, base);
}

#[cfg(feature = "ner-gliner")]
#[test]
fn deep_is_a_strict_superset_of_standard_on_generated_corpus() {
    let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        let names = Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap());
        let mut standard = Gate::for_grant_with_dictionary(&grant(mode), KEY, Arc::clone(&names));
        let mut deep =
            Gate::for_grant_with_deep_detector(&grant(mode), KEY, names, Arc::new(GeneratedDeep));
        for i in 0..2_000 {
            let email = format!("canary{i}@example.test");
            let text = format!("Asterian contact {email}; ordinarytag{i}");
            let base = standard.text(&text).expect("Standard issues text").0;
            let added = deep
                .text(&text)
                .expect("Deep fallback gate never refuses")
                .0;
            assert!(base.as_str().contains("ordinarytag"));
            assert!(!added.as_str().contains("ordinarytag"));
            assert!(
                added.as_str().contains("Asterian"),
                "names never added in {mode:?}"
            );
            assert_eq!(
                added.as_str().contains(&email),
                base.as_str().contains(&email),
                "Deep preserves Standard email handling in {mode:?}"
            );
        }
    }
}

#[cfg(feature = "ner-gliner")]
#[test]
fn deep_timeout_returns_standard_output_byte_for_byte() {
    let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
    let detector = Arc::new(BlockedDeep {
        release: std::sync::Mutex::new(release_rx),
        finished: finished_tx,
    });
    let empty = || Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap());
    let mut deep =
        Gate::for_grant_with_deep_detector(&grant(PrivacyMode::Private), KEY, empty(), detector);
    let mut standard = Gate::for_grant_with_dictionary(&grant(PrivacyMode::Private), KEY, empty());
    let text = "No private values in this sentence.";
    let expected = standard.text(text).unwrap().0.as_str().to_owned();
    assert_eq!(deep.text(text).unwrap().0.as_str(), expected);
    release_tx.send(()).unwrap();
    finished_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
}

#[cfg(feature = "ner-gliner")]
struct SleepingDeep {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    delay: std::time::Duration,
}

#[cfg(feature = "ner-gliner")]
impl Detector for SleepingDeep {
    fn detect(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::thread::sleep(self.delay);
        Ok(Vec::new())
    }
}

#[cfg(feature = "ner-gliner")]
#[test]
fn deep_deadline_covers_the_whole_text_operation_and_falls_back_to_standard() {
    let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut gate = Gate::for_grant_with_deep_detector(
        &grant(PrivacyMode::Private),
        KEY,
        Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap()),
        Arc::new(SleepingDeep {
            calls: Arc::clone(&calls),
            delay: std::time::Duration::from_secs(4),
        }),
    );
    let mut standard = Gate::for_grant_with_dictionary(
        &grant(PrivacyMode::Private),
        KEY,
        Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap()),
    );
    let text = "kept ⟦PERSON_AAAAAAAAAAAA⟧";
    let expected = standard.text(text).unwrap().0.as_str().to_owned();
    let start = std::time::Instant::now();
    let actual = gate.text(text).unwrap().0.as_str().to_owned();
    let elapsed = start.elapsed();
    eprintln!("4 s Deep operation: {elapsed:?}");
    assert!(elapsed <= std::time::Duration::from_millis(5_200));
    assert_eq!(actual, expected);
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[cfg(feature = "ner-gliner")]
#[test]
fn deep_detector_runs_once_for_plain_token_and_residue_paths() {
    let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut gate = Gate::for_grant_with_deep_detector(
        &grant(PrivacyMode::Private),
        KEY,
        Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap()),
        Arc::new(SleepingDeep {
            calls: Arc::clone(&calls),
            delay: std::time::Duration::from_millis(1),
        }),
    );
    gate.text("A short ordinary sentence.").unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    gate.text("kept ⟦PERSON_AAAAAAAAAAAA⟧").unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
    // Email masking enters the residue scan; that scan must stay on pass 1.
    gate.text("probe@example.test").unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 3);
}
