//! The configuration a local GLiNER2 recogniser is built from.

use std::path::PathBuf;

use super::labels::{
    DEFAULT_CHUNK_OVERLAP, DEFAULT_CHUNK_TOKENS, DEFAULT_MAX_WIDTH, DEFAULT_THRESHOLD,
    GLINER_PII_LABELS, LABEL_THRESHOLDS,
};

/// Everything [`GlinerRecognizer::load`](super::GlinerRecognizer::load) needs.
#[derive(Clone, Debug)]
pub struct GlinerConfig {
    /// Directory holding the ONNX graphs and the fast tokenizer.
    pub model_dir: PathBuf,
    /// ONNX graph inside `model_dir` (fp32 `model.onnx` by default).
    pub onnx_file: String,
    /// Fast tokenizer inside `model_dir`.
    pub tokenizer_file: String,
    /// Score floor for labels without an entry in `label_thresholds`; default
    /// [`DEFAULT_THRESHOLD`].
    pub threshold: f32,
    /// Per-label score floors; default [`LABEL_THRESHOLDS`].
    pub label_thresholds: Vec<(&'static str, f32)>,
    /// Entity labels sent in the prompt; default [`GLINER_PII_LABELS`].
    pub labels: Vec<&'static str>,
    /// ONNX Runtime shared library. When set and `ORT_DYLIB_PATH` is unset, it
    /// is exported for the process before the first session is created.
    pub ort_dylib: Option<PathBuf>,
    /// Maximum span width in words (checkpoint value).
    pub max_width: usize,
    /// Token window for a long text.
    pub chunk_tokens: usize,
    /// Token overlap between two windows.
    pub chunk_overlap: usize,
}

impl GlinerConfig {
    /// A config for one exported model directory, with the GLiNER2-PII labels,
    /// the default thresholds and the window sizes of the benchmark.
    pub fn new(model_dir: impl Into<PathBuf>) -> Self {
        Self {
            model_dir: model_dir.into(),
            onnx_file: "model.onnx".to_string(),
            tokenizer_file: "tokenizer.json".to_string(),
            threshold: DEFAULT_THRESHOLD,
            label_thresholds: LABEL_THRESHOLDS.to_vec(),
            labels: GLINER_PII_LABELS.to_vec(),
            ort_dylib: None,
            max_width: DEFAULT_MAX_WIDTH,
            chunk_tokens: DEFAULT_CHUNK_TOKENS,
            chunk_overlap: DEFAULT_CHUNK_OVERLAP,
        }
    }

    /// Override the default score floor. Labels with their own entry in
    /// `label_thresholds` keep it.
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Use the int8 dynamic-quantised graph instead of the fp32 one.
    pub fn with_int8(mut self) -> Self {
        self.onnx_file = "model_int8.onnx".to_string();
        self
    }

    /// Point at the ONNX Runtime shared library.
    pub fn with_ort_dylib(mut self, path: impl Into<PathBuf>) -> Self {
        self.ort_dylib = Some(path.into());
        self
    }

    /// Replace the entity labels.
    pub fn with_labels(mut self, labels: Vec<&'static str>) -> Self {
        self.labels = labels;
        self
    }

    /// The score floor for one label: its own entry, else the default.
    pub fn threshold_for(&self, label: &str) -> f32 {
        self.label_thresholds
            .iter()
            .find(|(name, _)| *name == label)
            .map(|(_, threshold)| *threshold)
            .unwrap_or(self.threshold)
    }
}
