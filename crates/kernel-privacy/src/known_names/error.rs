//! Why a known-names dictionary could not be compiled.

/// Why a known-names dictionary could not be compiled. The dictionary never
/// degrades to matching nothing: a caller that gets this error mounts no
/// dictionary, and a private gate then fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NameDictionaryError {
    /// The Aho-Corasick automaton rejected the compiled patterns.
    #[error("the known-names automaton could not be compiled")]
    Build,
}
