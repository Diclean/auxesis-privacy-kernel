//! Tests for loading, creating and validating `config.toml`.

use super::super::*;
use crate::i18n::Lang;
use tempfile::tempdir;

#[test]
fn creates_default_config_when_missing() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");

    let config = Config::load_or_create(&path).unwrap();
    assert_eq!(config, Config::default());
    assert!(path.exists(), "config file should be created");

    let again = Config::load_or_create(&path).unwrap();
    assert_eq!(again.version, 1);
    assert!(!again.brief.enabled);
    assert_eq!(again.brief.time, "08:00");
    assert_eq!(again.location, LocationConfig::default());
    assert_eq!(again.location.city, None);
    assert_eq!(again.location.country, None);
    assert_eq!(again.quiet.start, "22:00");
    assert_eq!(again.quiet.end, "07:00");
}

#[test]
fn explicit_location_in_an_existing_config_is_kept() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "version = 1\n[location]\ncity = \"Lyon\"\ncountry = \"FR\"\n",
    )
    .unwrap();
    let config = Config::load_or_create(&path).unwrap();
    assert_eq!(config.location.city.as_deref(), Some("Lyon"));
    assert_eq!(config.location.country.as_deref(), Some("FR"));
}

#[test]
fn ui_language_follows_the_system_and_reads_config_value() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "version = 1\n[ui]\nlanguage = \"fr\"\n").unwrap();
    assert_eq!(Config::load_or_create(&path).unwrap().ui.language, Lang::Fr);
    assert_eq!(Config::default().ui.language, Lang::from_env());

    std::fs::write(&path, "version = 1\n[ui]\nlanguage = \"de\"\n").unwrap();
    assert_eq!(Config::load_or_create(&path).unwrap().ui.language, Lang::En);
}

#[test]
fn rejects_invalid_brief_and_quiet_times() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[brief]\nenabled = true\ntime = '25:00'\n").unwrap();
    assert!(matches!(
        Config::load_or_create(&path),
        Err(ConfigError::InvalidLocalTime {
            field: "brief.time",
            ..
        })
    ));
    std::fs::write(&path, "[quiet]\nstart = '22:00'\nend = 'noon'\n").unwrap();
    assert!(matches!(
        Config::load_or_create(&path),
        Err(ConfigError::InvalidLocalTime {
            field: "quiet.end",
            ..
        })
    ));
}

#[test]
fn parses_valid_config() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "version = 2\nlog_level = \"debug\"\ndefault_agent = \"axis\"\n",
    )
    .unwrap();

    let config = Config::load_or_create(&path).unwrap();
    assert_eq!(config.version, 2);
    assert_eq!(config.log_level, "debug");
    assert_eq!(config.default_agent, "axis");
}

#[test]
fn legacy_default_dot_key_still_loads_as_default_agent() {
    let config: Config = toml::from_str("default_dot = \"axis\"\n").unwrap();
    assert_eq!(config.default_agent, "axis");
}

#[test]
fn fills_missing_fields_with_defaults() {
    use crate::budget::UsageKind;

    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "log_level = \"trace\"\n").unwrap();

    let config = Config::load_or_create(&path).unwrap();
    assert_eq!(config.log_level, "trace");
    assert_eq!(config.version, 1);
    assert_eq!(config.default_agent, "aux");
    // E-17: a config without `[budgets]` is capped by the conservative
    // defaults, not unlimited.
    assert!(!config.budgets.is_unset());
    assert_eq!(
        config.budgets.caps_for("main").limit(UsageKind::TokensIn),
        Some(crate::budget::DEFAULT_DAILY_TOKENS_IN)
    );
    assert_eq!(config.context, ContextConfig::default());
    assert_eq!(config.turn_timeout_secs, DEFAULT_TURN_TIMEOUT_SECS);
}

#[test]
fn default_config_round_trips_with_the_budgets_field() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let created = Config::load_or_create(&path).unwrap();
    assert_eq!(created, Config::default());

    let text = std::fs::read_to_string(&path).unwrap();
    let reparsed: Config = toml::from_str(&text).unwrap();
    assert_eq!(reparsed, created);
}

#[test]
fn rejects_broken_config() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "version = \"not a number\"\n").unwrap();

    let err = Config::load_or_create(&path).unwrap_err();
    assert!(matches!(err, ConfigError::Parse { .. }));
}

#[test]
fn a_shell_timeout_above_an_hour_is_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[shell]\ntimeout_secs = 3600\n").unwrap();
    let config = Config::load_or_create(&path).unwrap();
    assert_eq!(config.shell.timeout().as_secs(), 3600);
    std::fs::write(&path, "[shell]\ntimeout_secs = 3601\n").unwrap();
    let err = Config::load_or_create(&path).unwrap_err();
    assert!(
        matches!(err, ConfigError::ShellTimeoutTooLong { value: 3601 }),
        "{err}"
    );
    // u64::MAX is not even a TOML integer: refused at parse.
    std::fs::write(&path, "[shell]\ntimeout_secs = 18446744073709551615\n").unwrap();
    assert!(Config::load_or_create(&path).is_err());
    let huge = ShellConfig {
        timeout_secs: u64::MAX,
        ..ShellConfig::default()
    };
    assert_eq!(huge.timeout().as_secs(), 3600, "a built config is clamped");
}

#[test]
fn rejects_unknown_log_level() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "log_level = \"loud\"\n").unwrap();

    let err = Config::load_or_create(&path).unwrap_err();
    assert!(matches!(err, ConfigError::UnknownLogLevel { .. }));
}

#[test]
fn rejects_oversized_config() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let big = vec![b'#'; (MAX_CONFIG_BYTES + 1) as usize];
    std::fs::write(&path, big).unwrap();

    let err = Config::load_or_create(&path).unwrap_err();
    assert!(matches!(err, ConfigError::TooLarge { .. }));
}

#[cfg(unix)]
#[test]
fn rejects_char_device_config() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::os::unix::fs::symlink("/dev/null", &path).unwrap();

    let err = Config::load_or_create(&path).unwrap_err();
    assert!(matches!(err, ConfigError::NotRegularFile { .. }));
}

#[cfg(unix)]
#[test]
fn rejects_fifo_config_without_hanging() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let status = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo");
    assert!(status.success());

    let err = Config::load_or_create(&path).unwrap_err();
    assert!(matches!(err, ConfigError::NotRegularFile { .. }));
}
