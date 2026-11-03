//! Shared tools for the registry tests, one per classification shape.

use async_trait::async_trait;

use crate::{NativeTool, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, Trust};

pub(super) struct Dummy(pub(super) &'static str);

#[async_trait]
impl Tool for Dummy {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B5
    }
    fn name(&self) -> &str {
        self.0
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({"type": "object"})
    }

    async fn run(
        &self,
        _args: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok(self.0))
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn class(&self) -> ToolClass {
        ToolClass::default()
    }
}

pub(super) struct UntrustedDummy;

#[async_trait]
impl Tool for UntrustedDummy {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B5
    }
    fn name(&self) -> &str {
        "custom_reader"
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({"type": "object"})
    }

    async fn run(
        &self,
        _args: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok("outside content"))
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            output_trust: Trust::Untrusted,
            ..ToolClass::default()
        }
    }
}

pub(super) struct TrustedDummy(pub(super) &'static str);

#[async_trait]
impl Tool for TrustedDummy {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B5
    }
    fn name(&self) -> &str {
        self.0
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({"type": "object"})
    }

    async fn run(
        &self,
        _args: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok(self.0))
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            output_trust: Trust::Trusted,
            // Declared public, so the name-hook tests below stay meaningful.
            returns_private_data: false,
            ..ToolClass::default()
        }
    }
}

/// A tool that declares the private-data class flag.
pub(super) struct PrivateDummy(pub(super) &'static str);

#[async_trait]
impl Tool for PrivateDummy {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B5
    }
    fn name(&self) -> &str {
        self.0
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({"type": "object"})
    }

    async fn run(
        &self,
        _args: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok("private"))
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            output_trust: Trust::Trusted,
            returns_private_data: true,
            ..ToolClass::default()
        }
    }
}

/// A native tool with a fixed name, description and schema.
pub(super) struct Declared {
    pub(super) name: &'static str,
    pub(super) declared_name: &'static str,
}

#[async_trait]
impl Tool for Declared {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B5
    }
    fn name(&self) -> &str {
        self.name
    }

    fn schema(&self) -> serde_json::Value {
        self.native_schema().clone()
    }

    async fn run(
        &self,
        _args: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok(""))
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn class(&self) -> ToolClass {
        ToolClass::default()
    }
}

impl NativeTool for Declared {
    fn native_name(&self) -> &'static str {
        self.declared_name
    }

    fn native_description(&self) -> &'static str {
        "A declared tool."
    }

    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> =
            std::sync::LazyLock::new(|| serde_json::json!({"type": "object"}));
        std::sync::LazyLock::force(&SCHEMA)
    }
}

/// A tool whose class declares the skill floor.
pub(super) struct Classed(pub(super) &'static str);

#[async_trait]
impl Tool for Classed {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B5
    }

    fn name(&self) -> &str {
        self.0
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({"type": "object"})
    }

    async fn run(
        &self,
        _args: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok(self.0))
    }

    fn risk(&self) -> Risk {
        Risk::High
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            skill_only: true,
            ..ToolClass::default()
        }
    }
}
