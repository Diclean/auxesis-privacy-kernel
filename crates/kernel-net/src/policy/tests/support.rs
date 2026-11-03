//! Test helpers shared by the policy test modules.

use kernel_core::WebConfig;

use super::super::*;

pub(super) fn web_gate(config: WebConfig) -> WebGate {
    WebGate::new(config)
}
