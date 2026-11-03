//! The smaller config sections: Telegram, brief, location, memory, UI, quiet.

use crate::i18n::Lang;
use serde::{Deserialize, Serialize};

/// Telegram owner-only bot settings. The token is resolved from the
/// protected `~/.auxesis/.env` store and is never part of this config.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub owner_id: Option<i64>,
}

/// Morning brief schedule (`[brief]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BriefConfig {
    /// Master switch; false on fresh installs.
    pub enabled: bool,
    /// Local wall-clock time in `HH:MM` form.
    pub time: String,
}

impl Default for BriefConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            time: "08:00".to_string(),
        }
    }
}

/// Owner-selected city (`[location]`). Unset until the owner picks one: the
/// app never assumes where the owner lives.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, from = "RawLocationConfig")]
pub struct LocationConfig {
    /// City used by the weather source; `None` until the owner sets one.
    /// `default_city` is accepted too: the WhatsApp call tools read that key.
    pub city: Option<String>,
    /// ISO 3166-1 alpha-2 country code, when set.
    pub country: Option<String>,
}

/// On-disk `[location]`: `city` and the WhatsApp `default_city` key may both be
/// present (a serde alias would reject that as a duplicate field and stop the
/// daemon from starting), so read both and prefer `city`.
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawLocationConfig {
    city: Option<String>,
    default_city: Option<String>,
    country: Option<String>,
}

impl From<RawLocationConfig> for LocationConfig {
    fn from(raw: RawLocationConfig) -> Self {
        Self {
            city: raw.city.or(raw.default_city),
            country: raw.country,
        }
    }
}

/// Optional memory behavior (`[memory]` in `config.toml`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryConfig {
    /// Offer the model a tool for proposing stable facts for owner review.
    pub suggestions: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self { suggestions: true }
    }
}

/// User-interface settings (`[ui]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    /// Language used for notifications and scheduled messages.
    pub language: Lang,
}

impl Default for UiConfig {
    /// The system language, so a fresh install speaks the owner's language.
    fn default() -> Self {
        Self {
            language: Lang::from_env(),
        }
    }
}

/// Quiet hours (`[quiet]`), in local `HH:MM` time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct QuietConfig {
    /// Start of the quiet period.
    pub start: String,
    /// End of the quiet period.
    pub end: String,
}

impl Default for QuietConfig {
    fn default() -> Self {
        Self {
            start: "22:00".to_string(),
            end: "07:00".to_string(),
        }
    }
}
