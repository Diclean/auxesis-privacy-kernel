//! The error a model load or inference returns.

use std::fmt;

/// Why a [`GlinerRecognizer`](super::GlinerRecognizer) could not load or could not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlinerError {
    /// The configuration points at a directory or file that does not exist.
    MissingFile(String),
    /// The ONNX graph or its tokenizer could not be opened.
    Model(String),
    /// Tokenisation of a text failed.
    Tokenizer(String),
    /// The model ran but returned an error, or was given invalid input.
    Inference(String),
    /// A configuration value is invalid.
    Config(String),
}

impl fmt::Display for GlinerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GlinerError::MissingFile(path) => write!(f, "gliner: missing file: {path}"),
            GlinerError::Model(message) => write!(f, "gliner: model error: {message}"),
            GlinerError::Tokenizer(message) => write!(f, "gliner: tokenizer error: {message}"),
            GlinerError::Inference(message) => write!(f, "gliner: inference error: {message}"),
            GlinerError::Config(message) => write!(f, "gliner: config error: {message}"),
        }
    }
}

impl std::error::Error for GlinerError {}

impl From<gliner2_rs::Error> for GlinerError {
    fn from(error: gliner2_rs::Error) -> Self {
        match error {
            gliner2_rs::Error::MissingFile(path) => {
                GlinerError::MissingFile(path.display().to_string())
            }
            gliner2_rs::Error::Model(message) => GlinerError::Model(message),
            gliner2_rs::Error::Tokenizer(message) => GlinerError::Tokenizer(message),
            gliner2_rs::Error::Inference(message) => GlinerError::Inference(message),
            gliner2_rs::Error::InvalidOptions(message) => GlinerError::Config(message),
        }
    }
}
