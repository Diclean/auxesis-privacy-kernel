//! JSON at the gate: every string key and leaf masked, and a value whose key
//! gives it a secret's context treated as one secret.

use std::collections::BTreeSet;

use kernel_core::privacy::GrantPolicy;
use serde_json::{Map, Value};

use super::Gate;
use crate::anonymize::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
use crate::safetext::prohibited::SECRET_REMOVED;
use crate::safetext::report::{DetectError, DetectionReport, GateError};
use crate::safetext::tokens::{blank_minted, token_ranges};
use crate::span::{EntityKind, Span};

impl Gate {
    pub(super) fn map_value(
        &mut self,
        value: &Value,
    ) -> Result<(Value, DetectionReport), GateError> {
        Ok(match value {
            Value::String(text) => {
                let (masked, report) = self.mask(text)?;
                (Value::String(masked), report)
            }
            Value::Array(items) => {
                let mut report = DetectionReport::empty(self.policy);
                let mut masked = Vec::with_capacity(items.len());
                for item in items {
                    let (value, item_report) = self.map_value(item)?;
                    masked.push(value);
                    report.merge(item_report);
                }
                (Value::Array(masked), report)
            }
            Value::Object(fields) => {
                let mut report = DetectionReport::empty(self.policy);
                let mut masked = Map::new();
                for (key, field) in fields {
                    let (masked_key, key_report) = self.mask(key)?;
                    let (masked_field, field_report) = match field {
                        Value::String(value) => self.map_string_field(key, value)?,
                        _ => self.map_value(field)?,
                    };
                    report.merge(key_report);
                    report.merge(field_report);
                    masked.insert(masked_key, masked_field);
                }
                (Value::Object(masked), report)
            }
            other => (other.clone(), DetectionReport::empty(self.policy)),
        })
    }

    /// Mask one object entry's string value.
    ///
    /// The value is masked on its own, as any string leaf is, and the detector
    /// **also** reads the synthetic line `"<key>: <value>"`: a bare JSON value
    /// carries no key beside it, so the secret recogniser cannot tell what it
    /// is. When a `Secret` span in that line touches the value's bytes, the key
    /// gave the value a secret's context and the whole value is one secret: a
    /// single minted token under `Tokenised`, [`SECRET_REMOVED`] under
    /// `Passthrough`. A value over the secret read cap still fails closed in
    /// tokenised mode, exactly as the text path does.
    fn map_string_field(
        &mut self,
        key: &str,
        value: &str,
    ) -> Result<(Value, DetectionReport), GateError> {
        // The session's own tokens read as blanks, as in `mask_keeping`: a kept
        // token is no marker and gives the value no secret's context.
        let probe = match &self.session_tokens {
            Some(minted) => blank_minted(value, &token_ranges(value, minted)),
            None => blank_minted(value, &token_ranges(value, &BTreeSet::new())),
        };
        let synthetic = format!("{key}: {probe}");
        let value_start = key.len() + ": ".len();
        // TODO(DECODE-HARDEN-3): any Secret span touching the value promotes it,
        // so a marker-word span in a plain `body` masks the whole body; promote
        // only when the key itself gave the secret context.
        let secret = self
            .detector
            .detect_patterns(&synthetic)?
            .iter()
            .any(|span| {
                span.kind == EntityKind::Secret
                    && span.start < synthetic.len()
                    && value_start < span.end
            });
        if !secret {
            let (masked, report) = self.mask(value)?;
            return Ok((Value::String(masked), report));
        }
        // Fail closed on a secret-class value past the read cap, exactly as the
        // text path and the ordinary string path do; passthrough removes the
        // whole value below instead of returning it.
        if self.policy == GrantPolicy::Tokenised
            && (crate::recognizers::secrets::value_too_long(value)
                || crate::recognizers::secrets::value_too_long(&synthetic))
        {
            return Err(GateError::Detect(DetectError::TooLong));
        }
        let span = Span::new(EntityKind::Secret, 0, value.len(), 1.0, "json-key");
        let report = DetectionReport::of(self.policy, &[span]);
        let masked = match self.policy {
            GrantPolicy::Passthrough => Value::String(SECRET_REMOVED.to_string()),
            GrantPolicy::Tokenised => {
                let anonymizer = self.anonymizer.as_mut().ok_or(GateError::Key)?;
                let (token, is_new) = anonymizer.token_for(EntityKind::Secret, value);
                if is_new {
                    self.minted.push((token.clone(), value.to_string()));
                }
                Value::String(format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}"))
            }
        };
        Ok((masked, report))
    }
}
