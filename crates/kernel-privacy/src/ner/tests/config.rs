//! Configuration defaults and per-label thresholds.

use super::super::{GlinerConfig, GLINER_PII_LABELS, NAME_THRESHOLD};

#[test]
fn health_and_religion_thresholds_are_per_label() {
    let config = GlinerConfig::new("/models/gliner2");
    assert_eq!(config.threshold, 0.5);
    // NER-THRESH: only the model-only labels run at the low floor.
    for label in ["person", "organization", "address"] {
        assert_eq!(config.threshold_for(label), NAME_THRESHOLD, "{label}");
    }
    assert_eq!(config.threshold_for("health condition"), 0.4);
    for label in ["religion", "email", "iban", "payment_card", "phone_number"] {
        assert_eq!(config.threshold_for(label), 0.5, "{label}");
    }
    // Moving the default floor moves every label without its own override.
    let lowered = config.with_threshold(0.3);
    assert_eq!(lowered.threshold_for("religion"), 0.3);
    assert_eq!(lowered.threshold_for("person"), NAME_THRESHOLD);
    assert_eq!(lowered.threshold_for("health condition"), 0.4);
}

#[test]
fn config_defaults_are_the_benchmark_values() {
    let config = GlinerConfig::new("/models/gliner2");
    assert_eq!(config.threshold, 0.5);
    assert_eq!(config.labels, GLINER_PII_LABELS.to_vec());
    assert_eq!(config.onnx_file, "model.onnx");
    assert_eq!(config.chunk_tokens, 300);
    assert_eq!(config.chunk_overlap, 50);
    assert_eq!(
        GlinerConfig::new("/x").with_int8().onnx_file,
        "model_int8.onnx"
    );
}
