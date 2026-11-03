//! Loading, creating and validating `config.toml`, and the load errors.

use super::model::Config;
use super::shell::MAX_SHELL_TIMEOUT_SECS;
use super::toml_errors::redact_toml_error;
use std::io::Write;
use std::path::Path;
use thiserror::Error;

/// Refuse to read config files larger than this (protects against device
/// files and runaway writes).
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Log levels accepted in `Config::log_level`.
pub const LOG_LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

/// Errors while loading or creating the configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// I/O failure while reading or writing the config file.
    #[error("reading config: {0}")]
    Io(#[from] std::io::Error),
    /// The config path exists but is not a regular file (FIFO, device, ...).
    #[error("config path {path} is not a regular file")]
    NotRegularFile {
        /// Offending path.
        path: String,
    },
    /// The config file is too large to be a real config.
    #[error("config file {path} is unexpectedly large ({size} bytes)")]
    TooLarge {
        /// Offending path.
        path: String,
        /// Observed size.
        size: u64,
    },
    /// The config file exists but does not parse.
    #[error("parsing config at {path}: {}", source.message())]
    Parse {
        /// Path that failed to parse.
        path: String,
        /// Underlying TOML error, built by [`redact_toml_error`].
        source: toml::de::Error,
    },
    /// `log_level` is not one of the accepted values.
    /// The value is never kept: it came from the file (CONFIG-ERR-ECHO-1).
    #[error("invalid log_level (expected one of: error, warn, info, debug, trace)")]
    UnknownLogLevel {},
    /// A local-time setting is not valid `HH:MM`. The value is never kept.
    #[error("invalid local time for {field} (expected HH:MM)")]
    InvalidLocalTime { field: &'static str },
    /// `[shell] timeout_secs` is above [`MAX_SHELL_TIMEOUT_SECS`].
    #[error("[shell] timeout_secs = {value} is above the {MAX_SHELL_TIMEOUT_SECS} s maximum")]
    ShellTimeoutTooLong { value: u64 },
    /// Failure while serializing a default config.
    #[error("serializing config: {0}")]
    Serialize(#[from] toml::ser::Error),
}

impl Config {
    /// Load the config through the process's verified home (J-02 round 4):
    /// the read uses the fd's real path and the create goes through the
    /// fd-relative gateway, so a swapped home cannot plant or redirect
    /// `config.toml`.
    pub fn load_or_create_verified(home: &crate::paths::SandboxHome) -> Result<Self, ConfigError> {
        let real_home = home.real_path()?;
        let path = real_home.join("config.toml");
        match std::fs::metadata(&path) {
            Ok(_) => Self::load_or_create(&path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let config = Self::default();
                let text = toml::to_string_pretty(&config)?;
                home.write_atomic(Path::new("config.toml"), text.as_bytes(), 0o600)?;
                Ok(config)
            }
            Err(err) => Err(ConfigError::Io(err)),
        }
    }

    /// Load the config at `path`, creating it with defaults when missing.
    ///
    /// Refuses non-regular files (FIFOs, devices) and oversized files so a
    /// broken path can never hang the daemon or exhaust memory.
    pub fn load_or_create(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::metadata(path) {
            Ok(meta) => {
                if !meta.is_file() {
                    return Err(ConfigError::NotRegularFile {
                        path: path.display().to_string(),
                    });
                }
                if meta.len() > MAX_CONFIG_BYTES {
                    return Err(ConfigError::TooLarge {
                        path: path.display().to_string(),
                        size: meta.len(),
                    });
                }
                let text = std::fs::read_to_string(path)?;
                let config: Self = toml::from_str(&text).map_err(|err| ConfigError::Parse {
                    path: path.display().to_string(),
                    source: redact_toml_error(&err, "config.toml", &text),
                })?;
                config.validate()?;
                Ok(config)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let config = Self::default();
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                // `create_new` never follows a (dangling) symlink.
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?;
                file.write_all(toml::to_string_pretty(&config)?.as_bytes())?;
                drop(file);
                set_private_permissions(path)?;
                Ok(config)
            }
            Err(err) => Err(ConfigError::Io(err)),
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !LOG_LEVELS.contains(&self.log_level.as_str()) {
            return Err(ConfigError::UnknownLogLevel {});
        }
        for (field, value) in [
            ("brief.time", self.brief.time.as_str()),
            ("quiet.start", self.quiet.start.as_str()),
            ("quiet.end", self.quiet.end.as_str()),
        ] {
            if chrono::NaiveTime::parse_from_str(value, "%H:%M").is_err() {
                return Err(ConfigError::InvalidLocalTime { field });
            }
        }
        if self.shell.timeout_secs > MAX_SHELL_TIMEOUT_SECS {
            return Err(ConfigError::ShellTimeoutTooLong {
                value: self.shell.timeout_secs,
            });
        }
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
