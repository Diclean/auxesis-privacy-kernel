//! Name-based lookup for the tools the chat loop can call.
//!
//! [`ToolRegistry`] is split by topic into the modules below.

mod catalog;
mod classification;
mod constructors;
mod hooks;
mod skill_floor;
mod tool_registry;

pub use tool_registry::ToolRegistry;

#[cfg(test)]
mod tests;
