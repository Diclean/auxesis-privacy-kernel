//! Configuration model for an Auxesis installation.

mod acp;
mod approval;
mod context;
mod load;
mod model;
mod sections;
mod shell;
mod toml_errors;
mod web;

pub use acp::{
    AcpAgentConfig, AcpAuthMode, AcpConfig, DEFAULT_ACP_MAX_CPU_SECONDS,
    DEFAULT_ACP_MAX_FILE_BYTES, DEFAULT_ACP_MAX_MEMORY_BYTES, DEFAULT_ACP_MAX_OPEN_FILES,
    DEFAULT_ACP_MAX_OUTPUT_BYTES, DEFAULT_ACP_MAX_PROCESSES, DEFAULT_ACP_MAX_TURNS_PER_MINUTE,
    DEFAULT_ACP_MAX_TURNS_PER_TASK, DEFAULT_ACP_PERMISSION_TIMEOUT_SECS,
    DEFAULT_ACP_TURN_COST_ESTIMATE_CENTS, DEFAULT_ACP_TURN_TIMEOUT_SECS,
};
pub use approval::{ApprovalConfig, ApprovalMode, DEFAULT_APPROVAL_TIMEOUT_SECS};
pub use context::{ContextConfig, DEFAULT_CONTEXT_MAX_MESSAGES, DEFAULT_CONTEXT_MAX_TOKENS};
pub use load::{ConfigError, LOG_LEVELS, MAX_CONFIG_BYTES};
pub use model::{Config, DEFAULT_TURN_TIMEOUT_SECS};
pub use sections::{
    BriefConfig, LocationConfig, MemoryConfig, QuietConfig, TelegramConfig, UiConfig,
};
pub use shell::{ShellConfig, DEFAULT_SHELL_TIMEOUT_SECS, MAX_SHELL_TIMEOUT_SECS};
pub use toml_errors::{describe_toml_error, redact_toml_error, toml_error_kind};
pub use web::{
    WebConfig, WebMode, DEFAULT_WEB_ALLOW_EXPIRY_DAYS, DEFAULT_WEB_CONTENT_TYPES,
    DEFAULT_WEB_FETCHES_PER_DAY, DEFAULT_WEB_FETCHES_PER_TURN, DEFAULT_WEB_MAX_BYTES,
    DEFAULT_WEB_MAX_QUERY_BYTES, DEFAULT_WEB_MAX_REDIRECTS, DEFAULT_WEB_MAX_URL_BYTES,
    DEFAULT_WEB_MODE, DEFAULT_WEB_PER_HOST_PER_MINUTE, DEFAULT_WEB_PORTS, DEFAULT_WEB_TIMEOUT_SECS,
};

#[cfg(test)]
mod tests;
