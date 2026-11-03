//! The builder that assembles a registry of recognisers.

use crate::context::ContextEnhancer;
use crate::email_layer::EmailLayer;
use crate::recognizers;
use crate::threshold::Thresholds;

use super::detector::Recognizer;
use super::registry::Registry;

/// Incrementally builds a [`Registry`].
pub struct RegistryBuilder {
    pub(super) recognizers: Vec<Box<dyn Recognizer>>,
    pub(super) context: ContextEnhancer,
    pub(super) thresholds: Thresholds,
    pub(super) email_layer: Option<EmailLayer>,
}

impl RegistryBuilder {
    /// Mount a recogniser.
    pub fn with_recognizer<R: Recognizer + 'static>(mut self, recognizer: R) -> Self {
        self.recognizers.push(Box::new(recognizer));
        self
    }

    /// Mount an already-boxed recogniser.
    pub fn with_boxed_recognizer(mut self, recognizer: Box<dyn Recognizer>) -> Self {
        self.recognizers.push(recognizer);
        self
    }

    /// Mount every recogniser in the crate, including the unverified ones.
    pub fn with_all(mut self) -> Self {
        self.recognizers.extend(recognizers::all_recognizers());
        self
    }

    /// Override the context enhancer.
    pub fn context(mut self, context: ContextEnhancer) -> Self {
        self.context = context;
        self
    }

    /// Override the thresholds.
    pub fn thresholds(mut self, thresholds: Thresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Mount a custom email-aware layer.
    pub fn email_layer(mut self, email_layer: EmailLayer) -> Self {
        self.email_layer = Some(email_layer);
        self
    }

    /// Turn the email-aware layer off, reproducing the pre-1e pipeline.
    pub fn without_email_layer(mut self) -> Self {
        self.email_layer = None;
        self
    }

    /// Mask bare first names again (default `false`; config key `[privacy]
    /// mask_first_names`).
    ///
    /// The owner decision of 2026-10-09 keeps bare given names in clear; this
    /// switch restores the stricter pre-decision behaviour. A registry built
    /// without the email layer stays without it.
    pub fn mask_first_names(mut self, mask_first_names: bool) -> Self {
        self.email_layer = self
            .email_layer
            .map(|layer| layer.with_first_names(mask_first_names));
        self
    }

    /// Finish the registry.
    pub fn build(self) -> Registry {
        Registry {
            recognizers: self.recognizers,
            context: self.context,
            thresholds: self.thresholds,
            email_layer: self.email_layer,
            keep_names: true,
        }
    }
}
