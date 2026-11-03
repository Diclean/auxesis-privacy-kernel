//! K10: Standard-level recognisers for health and Art. 9 terms, bare Chinese
//! mobile numbers and API-key prefixes. Every value below is fictional.

mod health_forms;
mod health_terms;
mod helpers;
mod ids;
mod keys;
mod named_secrets;
mod pem_blocks;
mod perf;
mod phone;
mod reference;
mod wrapped_keys;

#[path = "../common/mod.rs"]
mod common;
