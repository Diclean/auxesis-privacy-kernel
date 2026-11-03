//! The vetted local model directory and the gate's second pass.

use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::safetext::{
    install_name_spotter, name_spotter_installed, BoundedSpotter, DetectError, NameSpotter,
};
use crate::span::Span;

use super::config::GlinerConfig;
use super::recognizer::GlinerRecognizer;

/// The ONNX Runtime library the product looks for next to the model.
const LOCAL_ORT_DYLIB: &str = "libonnxruntime.dylib";

/// Longest text the second pass reads. Above it a text keeps pass 1 only.
pub const MAX_SPOT_BYTES: usize = 64 * 1024;

/// How long the second pass may take on one text before the gate moves on.
pub const SPOT_DEADLINE: Duration = Duration::from_secs(5);

/// Why the model directory is not mounted.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Vetting {
    /// No model files: nothing to mount, checked again next time.
    Absent,
    /// Files exist but a path leaves the model directory, or is a symlink.
    Refused,
}

/// The config for the model under `model_dir`, only if every path stays inside
/// it and `model_dir` stays inside `root` (the home): no symlink at the
/// directory or at a file, each canonical path under its parent's canonical
/// path. `ORT_DYLIB_PATH` is honoured only when it resolves inside `model_dir`
/// (or in this crate's own tests); the dir's own dylib is used otherwise.
pub(super) fn vet_model_dir(root: &Path, model_dir: &Path) -> Result<GlinerConfig, Vetting> {
    let regular = |path: &Path| {
        std::fs::symlink_metadata(path)
            .map(|meta| meta.is_file())
            .unwrap_or(false)
    };
    let onnx = ["model.onnx", "model_int8.onnx"]
        .into_iter()
        .find(|file| model_dir.join(file).symlink_metadata().is_ok());
    let (Some(onnx), true) = (
        onnx,
        model_dir.join("tokenizer.json").symlink_metadata().is_ok(),
    ) else {
        return Err(Vetting::Absent);
    };
    let dir_is_plain = std::fs::symlink_metadata(model_dir)
        .map(|meta| meta.is_dir())
        .unwrap_or(false);
    let (Ok(root), Ok(dir)) = (root.canonicalize(), model_dir.canonicalize()) else {
        return Err(Vetting::Refused);
    };
    if !dir_is_plain || !dir.starts_with(&root) {
        return Err(Vetting::Refused);
    }
    let inside = |path: &Path| {
        path.canonicalize()
            .is_ok_and(|real| real.parent() == Some(&dir))
    };
    for file in [onnx, "tokenizer.json"] {
        let path = model_dir.join(file);
        if !regular(&path) || !inside(&path) {
            return Err(Vetting::Refused);
        }
    }
    let mut config = GlinerConfig::new(model_dir);
    config.onnx_file = onnx.to_string();
    let dylib = model_dir.join(LOCAL_ORT_DYLIB);
    match std::env::var_os("ORT_DYLIB_PATH") {
        Some(env) => {
            let real = PathBuf::from(env).canonicalize().ok();
            let in_dir = real.as_ref().is_some_and(|real| real.starts_with(&dir));
            if !in_dir && !cfg!(test) {
                return Err(Vetting::Refused);
            }
        }
        None if regular(&dylib) && inside(&dylib) => config = config.with_ort_dylib(dylib),
        None => {}
    }
    Ok(config)
}

/// Load the validated local model for the egress gate. Returns `None` when
/// absent or refused; callers should log a single path-free info message.
pub fn load_vetted_local_model(root: &Path, model_dir: &Path) -> Option<GlinerRecognizer> {
    let config = vet_model_dir(root, model_dir).ok()?;
    panic::catch_unwind(AssertUnwindSafe(|| GlinerRecognizer::load(config)))
        .ok()?
        .ok()
}

/// The product's second pass: the GLiNER2 model under one local directory,
/// loaded once on first use and shared. A load or inference failure is one log
/// line (never the text) and a [`DetectError::Names`]: the gate then keeps its
/// pass-1 spans. The directory is vetted again at load time.
struct LocalGliner {
    root: PathBuf,
    model_dir: PathBuf,
    model: OnceLock<Option<GlinerRecognizer>>,
    inference_logged: AtomicBool,
}

impl LocalGliner {
    fn model(&self) -> Option<&GlinerRecognizer> {
        self.model
            .get_or_init(|| {
                let loaded = vet_model_dir(&self.root, &self.model_dir)
                    .ok()
                    .and_then(|config| {
                        panic::catch_unwind(AssertUnwindSafe(|| GlinerRecognizer::load(config)))
                            .ok()
                    });
                match loaded {
                    Some(Ok(model)) => Some(model),
                    _ => {
                        eprintln!("auxesis: private mode: the local name model did not load; names are checked by pass 1 only");
                        None
                    }
                }
            })
            .as_ref()
    }
}

impl NameSpotter for LocalGliner {
    fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        let model = self.model().ok_or(DetectError::Names)?;
        match model.recognize(text) {
            Ok(spans) => Ok(spans),
            Err(_) => {
                if !self.inference_logged.swap(true, Ordering::Relaxed) {
                    eprintln!("auxesis: private mode: the local name model failed on a text; that text is checked by pass 1 only");
                }
                Err(DetectError::Names)
            }
        }
    }
}

/// Mount the second pass from `model_dir` (`model.onnx` or `model_int8.onnx`,
/// `tokenizer.json`, and `libonnxruntime.dylib` unless `ORT_DYLIB_PATH` points
/// inside it), which must stay inside `root` with no symlink on the way.
/// Nothing is loaded here and nothing is downloaded: the model loads on the
/// first tokenised text, on the bounded worker. Returns whether a second pass is
/// mounted. A directory without the model files, or one that fails the vetting,
/// mounts nothing and is checked again on the next call.
pub fn install_local_model(root: &Path, model_dir: &Path) -> bool {
    static ABSENT_LOGGED: AtomicBool = AtomicBool::new(false);
    static REFUSED_LOGGED: AtomicBool = AtomicBool::new(false);
    if name_spotter_installed() {
        return true;
    }
    match vet_model_dir(root, model_dir) {
        Ok(_) => {}
        Err(Vetting::Absent) => {
            if !ABSENT_LOGGED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "auxesis: private mode: no local name model; names are checked by pass 1 only"
                );
            }
            return false;
        }
        Err(Vetting::Refused) => {
            if !REFUSED_LOGGED.swap(true, Ordering::Relaxed) {
                eprintln!("auxesis: private mode: the local name model path was refused (symlink or outside the home); names are checked by pass 1 only");
            }
            return false;
        }
    }
    let local = LocalGliner {
        root: root.to_path_buf(),
        model_dir: model_dir.to_path_buf(),
        model: OnceLock::new(),
        inference_logged: AtomicBool::new(false),
    };
    install_name_spotter(Arc::new(BoundedSpotter::new(
        Arc::new(local),
        MAX_SPOT_BYTES,
        SPOT_DEADLINE,
    )));
    true
}
