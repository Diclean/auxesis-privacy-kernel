//! The frozen held-out sets: parsing, sha256 and the code pin.

use std::collections::HashSet;

use crate::cases::{in_scope, Case};

/// Maintainer-approved SHA-256 of the frozen held-out-2 data lines (excluding
/// line 1).
pub(crate) const HELDOUT_2_SHA256: &str =
    "8ed06af51b9d6bcc030d21421bdd7a59bfbba6eb3b9c6d76e5fed24700a64bef";

/// Read the frozen held-out-2 set. Line 1 hashes every byte after it, and both
/// that digest and the maintainer-approved code pin must match before scoring.
/// Returns the verified hash and the cases.
pub(crate) fn parse_heldout_2(text: &str) -> Result<(String, Vec<Case>), String> {
    let (head, body) = text.split_once('\n').unwrap_or((text, ""));
    let want = head
        .strip_prefix("# sha256: ")
        .ok_or("held-out-2: line 1 is not `# sha256: <hex>`")?
        .trim();
    let got = sha256_hex(body.as_bytes());
    if want != got {
        return Err(format!(
            "held-out-2: content sha256 {got} != header {want}: the frozen set was edited"
        ));
    }
    if got != HELDOUT_2_SHA256 {
        return Err(format!(
            "held-out-2: content sha256 {got} != code pin {HELDOUT_2_SHA256}; re-baselining needs a lead decision"
        ));
    }
    let cases = body
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| serde_json::from_str(line).map_err(|e| format!("held-out-2: {e}")))
        .collect::<Result<Vec<Case>, String>>()?;
    Ok((got, cases))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn validate_heldout_2_scope(cases: &[Case]) -> Result<(), String> {
    if let Some(case) = cases.iter().find(|case| !in_scope(&case.lang)) {
        return Err(format!(
            "held-out-2: out-of-scope case {} has language {}; re-baselining needs a lead decision",
            case.id, case.lang
        ));
    }
    Ok(())
}

/// Read the frozen held-out case ids.
pub(crate) fn load_heldout(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}
