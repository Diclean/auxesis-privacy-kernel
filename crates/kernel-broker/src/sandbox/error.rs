//! Why a command could not be launched, and how that refusal reaches the
//! model.

use super::limits::{DISABLED_MESSAGE, UNAVAILABLE_MESSAGE};
use crate::ToolError;
use thiserror::Error;

/// Why a command could not be launched.
#[derive(Debug, Error)]
pub enum LaunchError {
    /// Sandboxing was requested but `sandbox-exec` is missing/unsupported.
    #[error("{UNAVAILABLE_MESSAGE}")]
    Unavailable,
    /// Sandboxing was switched off without opting in to unsandboxed runs.
    #[error("{DISABLED_MESSAGE}")]
    SandboxDisabled,
    /// The workspace cannot be sandboxed safely (root, not a directory, ...).
    #[error("workspace {0} cannot be sandboxed safely")]
    UnsafeWorkspace(String),
    /// The workspace would expose a protected location (keys, keychains, the
    /// Auxesis home root, ...).
    #[error("workspace {0} overlaps a protected location")]
    SensitiveWorkspace(String),
    /// I/O failure while preparing the command.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Map a launch failure to the tool-facing error.
///
/// `Unavailable` / `SandboxDisabled` become a [`ToolError::Io`] carrying the
/// refusal message so the model reads exactly why nothing ran.
pub fn launch_error(err: LaunchError) -> ToolError {
    match err {
        LaunchError::Unavailable => ToolError::Io(std::io::Error::other(UNAVAILABLE_MESSAGE)),
        LaunchError::SandboxDisabled => ToolError::Io(std::io::Error::other(DISABLED_MESSAGE)),
        LaunchError::UnsafeWorkspace(path) | LaunchError::SensitiveWorkspace(path) => {
            ToolError::UnsafePath {
                path,
                reason: "shell workspace must be a real directory that does not overlap \
                         sensitive directories"
                    .to_string(),
            }
        }
        LaunchError::Io(err) => ToolError::Io(err),
    }
}
