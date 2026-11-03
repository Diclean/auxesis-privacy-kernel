//! The audit sink: one `tool.decision` event for every broker decision.

use thiserror::Error;

/// Errors returned by an [`AuditSink`].
#[derive(Debug, Error)]
pub enum AuditError {
    /// The sink could not record the event.
    #[error("audit sink failed: {0}")]
    Backend(String),
}

impl AuditError {
    /// Wrap a backend's own error message.
    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend(message.into())
    }
}

/// The audit trail behind the broker: one event per decision.
///
/// The kernel does not own a store. The app implements this trait over its
/// SQLite `events` table; `MemoryAuditSink` is the in-process test double.
/// Every decision the broker makes — allow, deny, both ask outcomes, approver
/// failures and edit substitutions — is logged as a `tool.decision` event
/// carrying the metadata-only JSON payload. The returned id is the new row.
pub trait AuditSink: Send + Sync {
    /// Record `payload` under `kind` and return the row id.
    fn log_event(&self, kind: &str, payload: &serde_json::Value) -> Result<i64, AuditError>;
}

/// In-memory [`AuditSink`] for tests: records every event, in order.
#[cfg(any(test, feature = "test-util"))]
#[derive(Default)]
pub struct MemoryAuditSink {
    events: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
}

#[cfg(any(test, feature = "test-util"))]
impl MemoryAuditSink {
    /// An empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every `(kind, payload)` recorded, in order.
    pub fn events(&self) -> Vec<(String, serde_json::Value)> {
        self.events.lock().unwrap().clone()
    }

    /// Payloads recorded for `kind`, in order.
    pub fn payloads(&self, kind: &str) -> Vec<serde_json::Value> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(recorded, _)| recorded == kind)
            .map(|(_, payload)| payload.clone())
            .collect()
    }

    /// How many events of `kind` were recorded.
    pub fn count(&self, kind: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(recorded, _)| recorded == kind)
            .count()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl AuditSink for MemoryAuditSink {
    fn log_event(&self, kind: &str, payload: &serde_json::Value) -> Result<i64, AuditError> {
        let mut events = self.events.lock().unwrap();
        events.push((kind.to_string(), payload.clone()));
        Ok(events.len() as i64)
    }
}

/// Errors returned by the broker itself.
#[derive(Debug, Error)]
pub enum BrokerError {
    /// Writing the audit record failed.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// The audit record could not be serialized.
    #[error("serializing audit record: {0}")]
    Serialize(#[from] serde_json::Error),
}
