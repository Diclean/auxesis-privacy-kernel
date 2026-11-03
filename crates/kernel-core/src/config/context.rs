//! The model-context window (`[context]`).

use serde::{Deserialize, Serialize};

/// Default newest-messages window the engine builds a model context from.
pub const DEFAULT_CONTEXT_MAX_MESSAGES: usize = 100;

/// Default soft token budget for that window (newest messages kept first).
pub const DEFAULT_CONTEXT_MAX_TOKENS: u64 = 32_000;

/// Model-context window (`[context]` in `config.toml`).
///
/// A resumed conversation sends only its newest messages to the provider: the
/// engine reads a bounded page from the store, keeps the system prompt, drops
/// leading orphaned tool results, and trims the oldest messages until both
/// bounds fit. Persisted history is **never** deleted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ContextConfig {
    /// Newest messages (system prompt excluded) kept in the model context.
    pub max_messages: usize,
    /// Soft token budget for that window, newest first.
    pub max_tokens: u64,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            max_messages: DEFAULT_CONTEXT_MAX_MESSAGES,
            max_tokens: DEFAULT_CONTEXT_MAX_TOKENS,
        }
    }
}
