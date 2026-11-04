//! The process-wide registry of known secret values: registration, LRU and
//! pin eviction, saturation, and the home/.env sources it loads values from.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

use aho_corasick::AhoCorasick;
use kernel_core::sync::{rwlock_read_recover, rwlock_write_recover};
use zeroize::Zeroizing;

use super::variants::secret_variants;
use super::*;

/// File under the Auxesis home holding headless `AUX_KEY_*` values.
pub(super) const ENV_FILE: &str = ".env";

/// A value longer than [`MAX_KNOWN_SECRET_LEN`] cannot be registered; the
/// refusal is logged once so an operator sees that a key is not covered
/// rather than assuming it is (R10).
static LONG_REFUSAL_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// File under the Auxesis home holding the API bearer token.
pub(super) const API_TOKEN_FILE: &str = "api.token";

/// One registered secret value: never printed, zeroed on drop.
///
/// The canonical value lives here wrapped in [`Zeroizing`]; the derived
/// match needles inside the automaton are a copy by construction (the
/// matcher must compare bytes) and live for the process lifetime by design.
pub(super) struct KnownSecret {
    value: Zeroizing<String>,
    /// Registration sequence (the pin table): a value is pinned by a live
    /// stream when its sequence is below the stream's pin cutoff.
    seq: u64,
    /// This value's needle variants, computed once at registration. The
    /// registry union is rebuilt on every mutation; recomputing every value's
    /// variants each time made a cap-sized fill quadratic.
    variants: BTreeSet<String>,
    /// The variant closure exceeded its byte budget, so not every spelling of
    /// this value is covered: live streams fail closed (mask the whole
    /// message) while it is registered.
    oversized: bool,
}

impl KnownSecret {
    pub(super) fn new(value: &str, seq: u64) -> Self {
        let (variants, oversized) = secret_variants(value);
        Self {
            variants,
            oversized,
            value: Zeroizing::new(value.to_string()),
            seq,
        }
    }

    pub(super) fn value(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for KnownSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KnownSecret(<redacted>)")
    }
}

/// The process-wide registry; empty means the layer is off.
#[derive(Default)]
pub(super) struct Registry {
    pub(super) values: Vec<KnownSecret>,
    pub(super) needles: BTreeSet<String>,
    pub(super) matcher: Option<AhoCorasick>,
    /// Set when values changed since the automaton was built and the registry
    /// is too large to rebuild inline; the next scrub rebuilds once, so a
    /// cap-sized fill batches instead of rebuilding per registration. Small
    /// registries (the startup keys) rebuild immediately, keeping the first
    /// scrub cheap.
    pub(super) matcher_dirty: bool,
    pub(super) max_needle_len: usize,
    /// Bumped on every mutation, so a caller may cache a scrub result and
    /// reuse it only while the registry it was computed against is intact.
    pub(super) generation: u64,
    /// Next pin epoch handed out by [`pin_known_secrets`].
    pub(super) next_pin: u64,
    /// Registration sequence the next value receives.
    pub(super) next_value_seq: u64,
    /// Live pin epochs and the registration-sequence cutoff each pinned: a
    /// value whose `seq` is below a cutoff existed when that pin was taken.
    /// Two `u64`s per live stream, shared here instead of one epoch per
    /// value per stream.
    pub(super) pins: BTreeMap<u64, u64>,
    /// Maximum cutoff over the live pins (`0` when none): a value is pinned
    /// exactly when `seq < max_pin_cutoff`.
    pub(super) max_pin_cutoff: u64,
    /// At least one registered value's variant closure exceeded its budget:
    /// live streams fail closed (whole-message placeholder) until it leaves
    /// the registry (R10).
    pub(super) oversized: bool,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts only: no needle ever reaches a formatter.
        f.debug_struct("Registry")
            .field("secrets", &self.values.len())
            .field("needles", &self.needles.len())
            .finish()
    }
}

fn registry() -> &'static RwLock<Registry> {
    static REGISTRY: OnceLock<RwLock<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(Registry::default()))
}

pub(super) fn read_registry() -> RwLockReadGuard<'static, Registry> {
    // A poisoned lock means a panic elsewhere; the registry itself is still
    // consistent (every mutation happens under the same lock).
    rwlock_read_recover(registry())
}

pub(super) fn write_registry() -> RwLockWriteGuard<'static, Registry> {
    rwlock_write_recover(registry())
}

/// Register one known secret value. Returns `true` when it was new.
///
/// Values shorter than [`MIN_KNOWN_SECRET_LEN`], longer than
/// [`MAX_KNOWN_SECRET_LEN`] or blank are refused; at [`MAX_KNOWN_SECRETS`]
/// the least recently registered value is evicted.
pub fn register_known_secret(value: &str) -> bool {
    register_values(std::iter::once(("explicit", value))).0 > 0
}

/// Register every value under one write lock, rebuilding the needle set and
/// the automaton **once** for the whole batch; per value it would be quadratic.
///
/// Returns `(registered, refused)`. A value that is already registered is
/// touched to the back of the eviction order: eviction is LRU, so the key
/// that is still being re-resolved is not the one dropped at the cap.
fn register_values<'a>(values: impl Iterator<Item = (&'a str, &'a str)>) -> (usize, usize) {
    let mut registry = write_registry();
    let mut registered = 0usize;
    let mut refused = 0usize;
    let mut changed = false;
    for (label, value) in values {
        let value = value.trim();
        if value.len() < MIN_KNOWN_SECRET_LEN
            || value.len() > MAX_KNOWN_SECRET_LEN
            || value.bytes().all(|byte| byte.is_ascii_whitespace())
        {
            if value.len() > MAX_KNOWN_SECRET_LEN
                && !LONG_REFUSAL_LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                // Never log the value itself, only the fact of the refusal.
                tracing::warn!(
                    limit = MAX_KNOWN_SECRET_LEN,
                    "a known-secret value is longer than the registration limit and is NOT scrubbed"
                );
            }
            refused += 1;
            continue;
        }
        if let Some(index) = registry
            .values
            .iter()
            .position(|secret| secret.value() == value)
        {
            // Still live: make it the newest entry so a rotated key evicts
            // something that has not been resolved recently.
            if index + 1 != registry.values.len() {
                let secret = registry.values.remove(index);
                registry.values.push(secret);
            }
            continue;
        }
        if registry.values.len() >= MAX_KNOWN_SECRETS {
            // Drop the least recently registered *unpinned* value so a
            // long-running daemon keeps picking up rotated keys at the cap,
            // while a value a live stream still relies on is never silently
            // un-registered. If every value is pinned the registry grows up to
            // the hard ceiling; a new value is refused and streams fail closed.
            let cutoff = registry.max_pin_cutoff;
            match registry
                .values
                .iter()
                .position(|secret| secret.seq >= cutoff)
            {
                Some(index) => {
                    registry.values.remove(index);
                }
                None if registry.values.len() >= MAX_KNOWN_SECRETS_HARD => {
                    refused += 1;
                    tracing::warn!(
                        "known-secret registry at its hard ceiling with every value pinned; refusing a new value (streams fail closed)"
                    );
                    continue;
                }
                None => {
                    tracing::debug!(
                        "known-secret registry past its cap with every value pinned by a live stream"
                    );
                }
            }
        }
        if value.len() >= LARGE_VALUE_WARN_BYTES {
            // Never the value itself: only the source label and its size. At
            // this length a composed spelling passes the needle cap, so the
            // value is flagged `registry_oversized` and every live stream
            // fails closed while it is registered (GLM-P3).
            tracing::warn!(
                source = label,
                bytes = value.len(),
                "a known-secret value is at least 400 bytes: its closure exceeds the per-value spelling cap, so live streams fail closed while it is registered"
            );
        }
        let seq = registry.next_value_seq;
        registry.next_value_seq = registry.next_value_seq.wrapping_add(1);
        registry.values.push(KnownSecret::new(value, seq));
        registered += 1;
        changed = true;
    }
    if changed {
        if registry.values.len() <= SMALL_REGISTRY_REBUILD {
            rebuild_registry(&mut registry);
        } else {
            registry.generation = registry.generation.wrapping_add(1);
            registry.matcher_dirty = true;
        }
    }
    (registered, refused)
}

/// Rebuild the needle set and automaton from the current values, and bump
/// the generation so cached scrub results are not reused. Each value's
/// variants are cached, so a cap-sized fill does not recompute every value's
/// spellings on every registration.
fn rebuild_registry(registry: &mut Registry) {
    registry.needles = registry
        .values
        .iter()
        .flat_map(|secret| secret.variants.iter().cloned())
        .collect();
    registry.max_needle_len = registry.needles.iter().map(String::len).max().unwrap_or(0);
    registry.matcher = build_matcher(&registry.needles);
    registry.oversized = registry.values.iter().any(|secret| secret.oversized);
    registry.matcher_dirty = false;
    registry.generation = registry.generation.wrapping_add(1);
}

/// Rebuild the automaton if registrations were batched.
pub(super) fn ensure_matcher(registry: &mut Registry) {
    if registry.matcher_dirty {
        rebuild_registry(registry);
    }
}

/// Registries at or below this size rebuild their automaton on every change
/// (startup keys, a handful of values); larger ones batch and rebuild on the
/// next scrub, so a cap-sized fill is linear instead of quadratic.
const SMALL_REGISTRY_REBUILD: usize = 8;

/// Registration warning threshold: a value of 410 bytes or more cannot have
/// every spelling covered (the `0x`-of-hex composition passes the 4096-byte
/// needle cap at 410 value bytes), so it is flagged [`registry_oversized`]
/// and every live stream fails closed while it is registered. The warning
/// names the source label, never the value (GLM-P3); 400 leaves margin.
const LARGE_VALUE_WARN_BYTES: usize = 400;

/// Pin every currently registered value for the lifetime of a live delta
/// stream.
///
/// While pinned, a value is never evicted by the LRU cap, so a mid-turn key
/// re-resolution, a sibling stream's registrations, or a rotation storm
/// cannot silently un-register a secret a live stream still relies on.
/// Returns the epoch to hand back to [`unpin_known_secrets`].
pub fn pin_known_secrets() -> u64 {
    let mut registry = write_registry();
    let epoch = registry.next_pin;
    registry.next_pin = registry.next_pin.wrapping_add(1);
    let cutoff = registry.next_value_seq;
    registry.pins.insert(epoch, cutoff);
    registry.max_pin_cutoff = registry.max_pin_cutoff.max(cutoff);
    epoch
}

/// Release a pin taken by [`pin_known_secrets`] and trim the registry back
/// to its cap by evicting the oldest unpinned values. Values registered
/// after the pin were never protected by it and are not touched.
pub fn unpin_known_secrets(epoch: u64) {
    let mut registry = write_registry();
    registry.pins.remove(&epoch);
    registry.max_pin_cutoff = registry.pins.values().copied().max().unwrap_or(0);
    let cutoff = registry.max_pin_cutoff;
    let mut trimmed = false;
    while registry.values.len() > MAX_KNOWN_SECRETS {
        match registry
            .values
            .iter()
            .position(|secret| secret.seq >= cutoff)
        {
            Some(index) => {
                registry.values.remove(index);
                trimmed = true;
            }
            None => break,
        }
    }
    if trimmed {
        if registry.values.len() <= SMALL_REGISTRY_REBUILD {
            rebuild_registry(&mut registry);
        } else {
            registry.generation = registry.generation.wrapping_add(1);
            registry.matcher_dirty = true;
        }
    }
}

/// True when the registry is at its hard ceiling with every value pinned by
/// a live stream: a new value cannot be registered without evicting a
/// pinned one, so a live delta stream must fail closed (emit a visible
/// placeholder) rather than publish unscrubbed text.
pub fn registry_saturated() -> bool {
    let registry = read_registry();
    let cutoff = registry.max_pin_cutoff;
    registry.values.len() >= MAX_KNOWN_SECRETS_HARD
        && registry.values.iter().all(|secret| secret.seq < cutoff)
}

/// True when a registered value's variant closure exceeded its budget: not
/// every spelling of that value is covered, so a live stream must fail closed
/// (emit a visible placeholder) rather than publish text it cannot prove
/// scrubbed (R10).
pub fn registry_oversized() -> bool {
    read_registry().oversized
}

/// True for the environment and `.env` names whose value is a secret this
/// process resolves: provider keys, the Telegram bot token, one mailbox
/// password per account (`AUX_MAIL_<ID>`; mail hosts and ports live in
/// `mail.toml`, never in `.env`) and an extension's OAuth token bundle
/// (`EXT_<NAME>__OAUTH_TOKENS`).
pub(super) fn is_known_secret_name(name: &str) -> bool {
    name.starts_with("AUX_KEY_")
        || name == "AUX_TELEGRAM_BOT_TOKEN"
        || name.starts_with("AUX_MAIL_")
        || name.ends_with("__OAUTH_TOKENS")
}

/// Collect one named secret, and for an OAuth bundle the access and refresh
/// tokens it holds: a provider error echoes a token on its own, not the whole
/// JSON line, so the leaves are registered as secrets of their own.
fn push_known_secret(values: &mut Vec<(String, Zeroizing<String>)>, name: &str, value: String) {
    if name.ends_with("__OAUTH_TOKENS") {
        if let Ok(serde_json::Value::Object(fields)) =
            serde_json::from_str::<serde_json::Value>(&value)
        {
            for key in ["access_token", "refresh_token"] {
                if let Some(serde_json::Value::String(token)) = fields.get(key) {
                    values.push((format!("{name}.{key}"), Zeroizing::new(token.clone())));
                }
            }
        }
    }
    values.push((name.to_owned(), Zeroizing::new(value)));
}

/// Register every known secret from `<home>/.env`, the process environment
/// (`AUX_KEY_*`, `AUX_TELEGRAM_BOT_TOKEN`, `AUX_MAIL_*` and
/// `EXT_*__OAUTH_TOKENS`) and `<home>/api.token`. Returns how many values
/// were new.
///
/// Called at daemon start and again whenever a key is re-resolved, so a
/// changed `.env` is picked up without a restart. Never returns or logs a
/// value; the count of values *refused* (too short, too long, blank)
/// is logged at debug so `registered=2` can be reconciled when a third key
/// exists in `.env`.
pub fn register_known_secrets_from_home(home: &Path) -> usize {
    let mut values: Vec<(String, Zeroizing<String>)> = Vec::new();
    for (name, value) in std::env::vars() {
        if is_known_secret_name(&name) {
            push_known_secret(&mut values, &name, value);
        }
    }
    if let Some(text) = read_small_file(&home.join(ENV_FILE)) {
        for (name, value) in dotenv_known_secret_values(&text) {
            push_known_secret(&mut values, &name, value);
        }
    }
    if let Some(token) = read_small_file(&home.join(API_TOKEN_FILE)) {
        values.push((
            API_TOKEN_FILE.to_string(),
            Zeroizing::new(token.trim().to_string()),
        ));
    }
    let (registered, refused) = register_values(
        values
            .iter()
            .map(|(label, value)| (label.as_str(), value.as_str())),
    );
    if refused > 0 {
        tracing::debug!(
            registered,
            refused,
            "known secrets refused at registration (shorter than 8 bytes, longer than 4096 or blank)"
        );
    }
    registered
}

/// Drop every registered secret (tests, key rotation). The values are zeroed
/// by their `Zeroizing` wrapper before the registry is replaced. The
/// generation is bumped so cached scrub results are not reused, and the pin
/// counter keeps rising so a released epoch can never collide with a new one.
pub fn clear_known_secrets() {
    let mut registry = write_registry();
    let generation = registry.generation.wrapping_add(1);
    let next_pin = registry.next_pin;
    *registry = Registry {
        generation,
        next_pin,
        ..Registry::default()
    };
}

/// Monotonic counter bumped whenever the registry changes. A caller that
/// caches a scrub result can reuse it only while this value is unchanged.
pub fn registry_generation() -> u64 {
    read_registry().generation
}

fn build_matcher(needles: &BTreeSet<String>) -> Option<AhoCorasick> {
    if needles.is_empty() {
        return None;
    }
    AhoCorasick::new(needles.iter()).ok()
}

/// Read a small regular file (never a FIFO/device, never more than 1 MiB).
fn read_small_file(path: &Path) -> Option<String> {
    const MAX_BYTES: u64 = 1024 * 1024;
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Every known-secret value from a dotenv file, quotes stripped like the
/// app's `DotEnvStore` does. The name filter is [`is_known_secret_name`], so
/// a new secret family is read here as soon as it is added there.
fn dotenv_known_secret_values(text: &str) -> Vec<(String, String)> {
    let mut values = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !is_known_secret_name(name) {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|rest| rest.strip_suffix('\''))
            })
            .unwrap_or(value);
        if !value.is_empty() {
            values.push((name.to_string(), value.to_string()));
        }
    }
    values
}
