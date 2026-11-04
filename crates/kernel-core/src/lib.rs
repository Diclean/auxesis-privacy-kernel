//! The privacy policy of the Auxesis kernel: the privacy modes, the one id
//! per path out ([`privacy::PathId`]), the single decision point
//! ([`privacy::admit`]) and the unforgeable [`privacy::Grant`] it returns.
//! [`privacy`] is the policy table and the gate; [`paths`] is the install
//! layout and the sandbox guard that keeps a process off the real home;
//! [`text`] and [`sync`] are the shared primitives the gate and the kernel's
//! other crates use.
//!
//! # Shared app plumbing
//!
//! The Auxesis app uses the modules below. They are plumbing, not the privacy
//! gate: whether a path may send, and in which mode, is decided in [`privacy`].
//!
//! - [`budget`] — daily spend caps and the guard that refuses an over-budget
//!   call.
//! - [`config`] — the `config.toml` model; its web and TOML settings are shared
//!   with the other kernel crates, and its Telegram, Brief, Location, memory,
//!   UI and Quiet sections are app-only.
//! - [`config_lock`] — the cross-process lock for edits to `config.toml` and
//!   `.env`.
//! - [`endpoint`] — one loopback endpoint resolver for the CLI and `aux doctor`.
//! - [`env_file`] — named reads from the protected `~/.auxesis/.env`.
//! - [`i18n`] — the typed English and French message catalogue.
//! - [`job`] — interval and daily schedules for the scheduler.
//! - [`keychain`] — the opt-in, sandbox-guarded macOS Keychain bridge; default
//!   deny.
//! - [`killswitch`] — the `STOP` marker and `is_stopped()`; a stop signal the
//!   app checks before a step, not an egress gate: `admit()` never reads it.
//! - [`logging`] — log-filter defaults that silence the HTML and XML parser
//!   crates.
#![doc = include_str!("../README.md")]

// The policy: the gate, the paths it protects, and shared primitives.
pub mod paths;
pub mod privacy;
pub mod sync;
pub mod text;

// Shared app plumbing: the app uses these; none is the privacy gate.
pub mod budget;
pub mod config;
pub mod config_lock;
pub mod endpoint;
pub mod env_file;
pub mod i18n;
pub mod job;
pub mod keychain;
pub mod killswitch;
pub mod logging;

pub use budget::{
    audit_denial, warning_threshold, AuditSink, BudgetCaps, BudgetError, BudgetGuard, Budgets,
    Decision, Denial, DenialReason, Reservation, ReservationLedger, ReserveOutcome, UsageActual,
    UsageKind, UsageLedger, UsageTotals, DEFAULT_DAILY_TOKENS_IN, DEFAULT_DAILY_TOKENS_OUT,
    DEFAULT_DAILY_USD_CENTS, ESTIMATED_UNIT, RESERVATION_TTL,
};
pub use config::{
    describe_toml_error, redact_toml_error, toml_error_kind, BriefConfig, Config, ConfigError,
    ContextConfig, LocationConfig, QuietConfig, ShellConfig, TelegramConfig, UiConfig, WebConfig,
    WebMode, DEFAULT_WEB_ALLOW_EXPIRY_DAYS, DEFAULT_WEB_CONTENT_TYPES, DEFAULT_WEB_FETCHES_PER_DAY,
    DEFAULT_WEB_FETCHES_PER_TURN, DEFAULT_WEB_MAX_BYTES, DEFAULT_WEB_MAX_QUERY_BYTES,
    DEFAULT_WEB_MAX_REDIRECTS, DEFAULT_WEB_MAX_URL_BYTES, DEFAULT_WEB_PER_HOST_PER_MINUTE,
    DEFAULT_WEB_PORTS, DEFAULT_WEB_TIMEOUT_SECS,
};
pub use config_lock::{with_config_lock, ConfigLockError, CONFIG_LOCK_FILE, CONFIG_LOCK_TIMEOUT};
pub use endpoint::{resolve_client_endpoint, ClientEndpoint, API_PORT_ENV};
pub use i18n::{Lang, Message};
pub use job::{Schedule, ScheduleError};
pub use paths::{
    auxesis_home, config_path, ensure_home, ensure_sandbox_guard, ensure_sandbox_home,
    ensure_sandbox_port, log_dir, real_user_home, sandbox_guard_active, store_path,
    verified_child_path, verified_home, verified_home_for, verified_home_or_verify, SandboxHome,
    REAL_DAEMON_PORT,
};
pub use sync::{lock_recover, rwlock_read_recover, rwlock_write_recover};
pub use text::{clean_field, sanitize_text, truncate_chars};

/// Version of the Auxesis workspace, taken from Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
