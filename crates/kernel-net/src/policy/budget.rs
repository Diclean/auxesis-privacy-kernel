//! The per-turn, per-day and per-host fetch counters.

use kernel_core::WebConfig;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use super::decision::DenyReason;

/// Which counter refused a fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetKind {
    /// Per-turn cap.
    Turn,
    /// Per-day cap.
    Day,
    /// Per-host rolling-minute cap.
    Host,
}

impl BudgetKind {
    /// The [`DenyReason`] this counter maps to.
    pub fn deny_reason(self) -> DenyReason {
        match self {
            BudgetKind::Turn => DenyReason::BudgetTurn,
            BudgetKind::Day => DenyReason::BudgetDay,
            BudgetKind::Host => DenyReason::BudgetHost,
        }
    }
}

/// In-memory fetch counters. `reserve` is called **before** the connect, so a
/// fetch that is over budget never opens a socket. The counters live in
/// memory (per conversation); a persistent day ledger does not exist yet.
#[derive(Debug, Default)]
pub struct WebBudget {
    turn: u32,
    day: u32,
    day_key: String,
    per_host: BTreeMap<String, VecDeque<Instant>>,
}

impl WebBudget {
    /// A fresh budget with every counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the per-turn counter. Called once at the start of each turn.
    pub fn start_turn(&mut self) {
        self.turn = 0;
    }

    /// Point the per-day counter at `key` (a local-day string). A different
    /// key resets the day counter.
    pub fn set_day(&mut self, key: &str) {
        if self.day_key != key {
            self.day_key = key.to_string();
            self.day = 0;
        }
    }

    /// The per-turn count so far (tests and diagnostics).
    pub fn turn_count(&self) -> u32 {
        self.turn
    }

    /// Reserve one fetch for `host`, or return the counter that refused it.
    pub fn reserve(
        &mut self,
        host: &str,
        now: Instant,
        config: &WebConfig,
    ) -> Result<(), BudgetKind> {
        if self.turn >= config.fetches_per_turn {
            return Err(BudgetKind::Turn);
        }
        if self.day >= config.fetches_per_day {
            return Err(BudgetKind::Day);
        }
        let window = Duration::from_secs(60);
        let recent = self.per_host.entry(host.to_string()).or_default();
        while let Some(front) = recent.front() {
            if now.saturating_duration_since(*front) >= window {
                recent.pop_front();
            } else {
                break;
            }
        }
        if recent.len() as u32 >= config.per_host_per_minute {
            return Err(BudgetKind::Host);
        }
        self.turn += 1;
        self.day += 1;
        recent.push_back(now);
        Ok(())
    }

    /// The per-day count so far (tests and diagnostics).
    pub fn day_count(&self) -> u32 {
        self.day
    }

    /// Whether one fetch for each of `hosts` would fit every counter, without
    /// reserving anything. The engine asks this before it shows an approval
    /// card; the fetcher reserves each destination when it connects, so a
    /// refused or unapproved call never consumes a slot.
    pub fn check(
        &self,
        hosts: &[&str],
        now: Instant,
        config: &WebConfig,
    ) -> Result<(), BudgetKind> {
        let needed = hosts.len() as u32;
        if self.turn + needed > config.fetches_per_turn {
            return Err(BudgetKind::Turn);
        }
        if self.day + needed > config.fetches_per_day {
            return Err(BudgetKind::Day);
        }
        let window = Duration::from_secs(60);
        let mut wanted: BTreeMap<&str, u32> = BTreeMap::new();
        for host in hosts {
            *wanted.entry(*host).or_default() += 1;
        }
        for (host, count) in wanted {
            let recent = self.per_host.get(host).map_or(0, |recent| {
                recent
                    .iter()
                    .filter(|reserved| now.saturating_duration_since(**reserved) < window)
                    .count() as u32
            });
            if recent + count > config.per_host_per_minute {
                return Err(BudgetKind::Host);
            }
        }
        Ok(())
    }
}
