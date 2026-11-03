//! Test-only helpers shared by the `config` submodule tests.

#[cfg(test)]
pub(super) mod shared {
    pub(in crate::config) fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }
}
