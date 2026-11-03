//! Tests for the shell, ACP, Telegram and location sections.

use super::super::*;
use tempfile::tempdir;

#[test]
fn shell_sandbox_defaults_are_safe() {
    let config = Config::default();
    assert!(config.shell.sandbox, "sandbox on by default");
    assert!(!config.shell.network, "network off by default");
    assert!(!config.shell.allow_unsandboxed, "fail closed by default");
    assert_eq!(config.shell.timeout().as_secs(), 30, "30 s wall clock");
}

#[test]
fn acp_is_off_by_default_and_parses_the_section() {
    let config = Config::default();
    assert!(!config.acp.enabled, "ACP must be off by default");
    assert!(config.acp.agents.is_empty());
    assert_eq!(
        config.acp.turn_timeout().as_secs(),
        DEFAULT_ACP_TURN_TIMEOUT_SECS
    );
    assert_eq!(
        config.acp.max_turns_per_task,
        DEFAULT_ACP_MAX_TURNS_PER_TASK
    );
    assert_eq!(
        config.acp.max_turns_per_minute,
        DEFAULT_ACP_MAX_TURNS_PER_MINUTE
    );
    assert_eq!(
        config.acp.turn_cost_estimate_cents,
        DEFAULT_ACP_TURN_COST_ESTIMATE_CENTS
    );
    assert_eq!(config.acp.max_cpu_seconds, DEFAULT_ACP_MAX_CPU_SECONDS);
    assert_eq!(config.acp.max_file_bytes, DEFAULT_ACP_MAX_FILE_BYTES);
    assert_eq!(config.acp.max_open_files, DEFAULT_ACP_MAX_OPEN_FILES);
    assert_eq!(config.acp.max_processes, DEFAULT_ACP_MAX_PROCESSES);
    assert_eq!(config.acp.max_memory_bytes, DEFAULT_ACP_MAX_MEMORY_BYTES);

    let parsed: Config = toml::from_str(
        r#"
            version = 1
            [acp]
            enabled = true
            turn_timeout_secs = 30
            max_turns_per_task = 2
            max_turns_per_minute = 3
            max_cpu_seconds = 45
            max_file_bytes = 2048
            max_open_files = 64
            max_processes = 8
            max_memory_bytes = 4096

            [acp.agents.opencode]
            command = "opencode"
            args = ["acp"]
            provider_id = "opencode-go"
            vendor_data_dir = "~/.local/share/opencode"

            [acp.agents.claude]
            command = "claude-agent-acp"
            auth = "api-key"
            "#,
    )
    .unwrap();
    assert!(parsed.acp.enabled);
    assert_eq!(parsed.acp.turn_timeout().as_secs(), 30);
    assert_eq!(parsed.acp.max_turns_per_task, 2);
    assert_eq!(parsed.acp.max_turns_per_minute, 3);
    assert_eq!(parsed.acp.max_cpu_seconds, 45);
    assert_eq!(parsed.acp.max_file_bytes, 2048);
    assert_eq!(parsed.acp.max_open_files, 64);
    assert_eq!(parsed.acp.max_processes, 8);
    assert_eq!(parsed.acp.max_memory_bytes, 4096);
    let opencode = parsed.acp.agents.get("opencode").unwrap();
    assert_eq!(opencode.command, "opencode");
    assert_eq!(opencode.args, vec!["acp".to_string()]);
    assert_eq!(opencode.auth, AcpAuthMode::CliLogin);
    assert_eq!(opencode.provider_id.as_deref(), Some("opencode-go"));
    assert_eq!(
        parsed.acp.agents.get("claude").unwrap().auth,
        AcpAuthMode::ApiKey
    );

    // Round-trip: the default config serializes and parses back equal.
    let text = toml::to_string(&Config::default()).unwrap();
    let reparsed: Config = toml::from_str(&text).unwrap();
    assert_eq!(reparsed, Config::default());
}

#[test]
fn parses_the_shell_section() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "version = 1\n\n[shell]\nnetwork = true\nallow_unsandboxed = true\ntimeout_secs = 120\n",
    )
    .unwrap();

    let config = Config::load_or_create(&path).unwrap();
    assert!(config.shell.sandbox, "sandbox stays on unless disabled");
    assert!(config.shell.network);
    assert!(config.shell.allow_unsandboxed);
    assert_eq!(config.shell.timeout().as_secs(), 120);

    let text = std::fs::read_to_string(&path).unwrap();
    let reparsed: Config = toml::from_str(&text).unwrap();
    assert_eq!(reparsed, config);
}

#[test]
fn telegram_channel_defaults_off_and_accepts_explicit_config() {
    let default = Config::default();
    assert!(!default.telegram.enabled);
    let enabled: Config = toml::from_str("[telegram]\nenabled = true\nowner_id = 42\n").unwrap();
    assert!(enabled.telegram.enabled);
    assert_eq!(enabled.telegram.owner_id, Some(42));
}

#[test]
fn location_accepts_city_and_default_city_together() {
    let both: Config =
        toml::from_str("[location]\ncity = \"Lyon\"\ndefault_city = \"Pecs\"\n").unwrap();
    assert_eq!(both.location.city.as_deref(), Some("Lyon"));
    let wa_only: Config = toml::from_str("[location]\ndefault_city = \"Pecs\"\n").unwrap();
    assert_eq!(wa_only.location.city.as_deref(), Some("Pecs"));
    let unset: Config = toml::from_str("").unwrap();
    assert_eq!(unset.location.city, None);
}
