//! Deep detection: model and ONNX Runtime discovery, registry loading.

#[cfg(feature = "ner-gliner")]
use std::env;
#[cfg(feature = "ner-gliner")]
use std::path::PathBuf;
use std::sync::Arc;

use kernel_privacy::Registry;

/// Where the exported GLiNER checkpoint lives, when it is installed.
#[cfg(feature = "ner-gliner")]
fn find_gliner_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for key in [
        "PRIVACY_EVAL_GLINER_DIR",
        "AUX_GLINER_DIR",
        "GLINER_MODEL_DIR",
    ] {
        if let Some(value) = env::var_os(key) {
            candidates.push(PathBuf::from(value));
        }
    }
    if let Some(home) = env::var_os("AUXESIS_HOME") {
        candidates.push(PathBuf::from(home).join("models/gliner2-pii"));
    }
    // The model is never bundled in the repository.
    if let Some(home) = env::var_os("HOME") {
        candidates.push(PathBuf::from(&home).join("models/gliner2-pii"));
        candidates.push(PathBuf::from(&home).join(".auxesis/models/gliner2-pii"));
        candidates.push(PathBuf::from(home).join(".auxesis/models/gliner-multi-pii-v1"));
    }
    candidates.push(PathBuf::from("models/gliner-multi-pii-v1"));
    candidates.push(PathBuf::from("vendor/gliner-multi-pii-v1"));
    candidates.into_iter().find(|dir| {
        (dir.join("model.onnx").is_file() || dir.join("model_int8.onnx").is_file())
            && dir.join("tokenizer.json").is_file()
    })
}

/// The ONNX Runtime shared library, when one is installed.
#[cfg(feature = "ner-gliner")]
fn find_ort_dylib() -> Option<PathBuf> {
    if let Some(value) = env::var_os("ORT_DYLIB_PATH") {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Some(path);
        }
    }
    [
        "/usr/lib/libonnxruntime.so",
        "/usr/local/lib/libonnxruntime.so",
        "vendor/onnxruntime/lib/libonnxruntime.so",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
}

/// The Standard pipeline plus GLiNER, when the feature and the model exist.
#[cfg(feature = "ner-gliner")]
pub(crate) fn load_deep() -> Result<Arc<Registry>, String> {
    use kernel_privacy::{GlinerConfig, GlinerRecognizer};

    let model_dir = find_gliner_dir().ok_or_else(|| "no GLiNER model directory".to_string())?;
    let mut config = GlinerConfig::new(model_dir);
    if let Some(dylib) = find_ort_dylib() {
        config = config.with_ort_dylib(dylib);
    }
    let gliner = GlinerRecognizer::load(config).map_err(|error| error.to_string())?;
    Ok(Arc::new(
        Registry::builder()
            .with_all()
            .with_boxed_recognizer(Box::new(gliner))
            .build(),
    ))
}

/// Without the feature, Deep detection is never available.
#[cfg(not(feature = "ner-gliner"))]
pub(crate) fn load_deep() -> Result<Arc<Registry>, String> {
    Err("built without the ner-gliner feature".to_string())
}
