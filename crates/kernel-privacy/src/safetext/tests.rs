//! Unit tests for the gate's public surface and the private helpers it grew up
//! with. Shared helpers live here; the two groups of tests are child modules.

use super::*;
use crate::recognizer::Registry;
use crate::safetext::prohibited::is_hash_fragment;
use crate::span::{EntityKind, Span};
use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const KEY: [u8; 32] = [9u8; 32];

#[test]
fn hash_fragment_exclusion_is_bounded_and_masks_overlong_runs() {
    let text = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let span = Span::new(
        EntityKind::Iban,
        0,
        15,
        crate::recognizers::iban::SHAPE_SCORE,
        "iban",
    );
    assert!(is_hash_fragment(text, &span));

    let long = "a".repeat(1024);
    let span = Span::new(
        EntityKind::Iban,
        400,
        415,
        crate::recognizers::iban::SHAPE_SCORE,
        "iban",
    );
    assert!(!is_hash_fragment(&long, &span));
}

/// A real grant, minted the way production does. C9 is covered and allowed
/// in both modes, so a test can pick the policy it exercises.
fn grant(mode: PrivacyMode) -> Grant {
    let ctx = Context {
        destination: Destination::LocalDisplay,
    };
    match admit(PathId::C9, mode, &ctx) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow, got {other:?}"),
    }
}

/// An open-mode gate: the detectors run, nothing is masked.
fn passthrough_gate() -> Gate {
    Gate::for_grant(&grant(PrivacyMode::Open), KEY)
}

/// A passthrough gate over a detector with no name coverage at all: the
/// pre-Standard view, kept to test [`NameCoverage::NotChecked`].
fn passthrough_gate_without_names() -> Gate {
    Gate::for_tests(&grant(PrivacyMode::Open), KEY, Arc::new(Registry::new()))
}

/// A private-mode gate over an injected detector: masking needs a name
/// detector, so tests inject one.
fn tokenising_gate(key: [u8; 32], detector: Arc<dyn Detector>) -> Gate {
    Gate::for_tests(&grant(PrivacyMode::Private), key, detector)
}

/// The default deterministic registry, claiming name coverage, so the
/// tokenising path can be exercised without GLiNER.
struct NamesClaimed(Registry);

impl NamesClaimed {
    fn new() -> Self {
        Self(Registry::new())
    }
}

impl Detector for NamesClaimed {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.0.detect(text)
    }

    fn checks_names(&self) -> bool {
        true
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.0.residue(text)
    }
}

fn masking_gate() -> Gate {
    tokenising_gate(KEY, Arc::new(NamesClaimed::new()))
}

/// A detector that always fails, to exercise the fail-closed path.
struct Broken;

impl Detector for Broken {
    fn detect(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
        Err(DetectError::Panicked)
    }

    /// A tokenising gate refuses before detection when names are
    /// unchecked; these probes stand in for the full stack.
    fn checks_names(&self) -> bool {
        true
    }
}

/// Detects like [`NamesClaimed`], but its residue view fails from the
/// second call on: the rounds that add export columns.
struct FailsLate(NamesClaimed, std::sync::atomic::AtomicUsize);

impl Detector for FailsLate {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.0.detect(text)
    }

    fn checks_names(&self) -> bool {
        true
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        if self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
            return Err(DetectError::Panicked);
        }
        self.0.residue(text)
    }
}

mod gate;
mod values;
