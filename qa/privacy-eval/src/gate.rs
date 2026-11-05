//! Gate output checks: whether a gold value is still readable.

use kernel_privacy::eval::GoldSpan;

/// Letters and digits of `text`, lower-cased.
pub(crate) fn skeleton(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// The gate output without its tokens (`⟦…⟧`) and removal markers (`[… removed]`).
pub(crate) fn clear_of(out: &str) -> String {
    let (head, tokens) = out.split_once('⟦').unwrap_or((out, ""));
    let mut text = head.to_string();
    for part in tokens.split('⟦') {
        text.push_str(part.split_once('⟧').map_or("", |(_, rest)| rest));
    }
    while let Some(end) = text.find(" removed]") {
        let start = text[..end].rfind('[').unwrap_or(end);
        text.replace_range(start..end + " removed]".len(), " ");
    }
    text
}

/// Whether the gold value can still be read in what the gate issued: the value
/// itself, or a run of 6 of its letters and digits (all of them when shorter)
/// that the rest of the text did not already hold. This is the LEAK-FINDER-1
/// rule on Unicode letters, so a partial mask is a miss and a Han term counts.
pub(crate) fn leaked(text: &str, gold: &GoldSpan, issued: &str) -> bool {
    let value = text.get(gold.start..gold.end).unwrap_or("");
    if issued.contains(value) {
        return true;
    }
    let rest = format!("{} {}", &text[..gold.start], &text[gold.end..]);
    let (seed, rest, out) = (
        skeleton(value),
        skeleton(&rest),
        skeleton(&clear_of(issued)),
    );
    let seed: Vec<char> = seed.chars().collect();
    let k = seed.len().min(6);
    k > 0
        && seed.windows(k).any(|run| {
            let run: String = run.iter().collect();
            out.contains(&run) && !rest.contains(&run)
        })
}

/// What the gate did with one gold value.
///
/// A partial mask lands in [`Outcome::Leaked`]: the 6-character run is the only
/// read test the scorer has, so it cannot tell a half mask from a full leak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The text went through and no readable run of the value is left.
    Masked,
    /// The text went through and a run of 6 (all, when shorter) is readable.
    Leaked,
    /// The gate refused the whole text, so it issued nothing.
    Blocked,
}

/// Classify one gold value from what the gate issued, if anything.
pub(crate) fn outcome(text: &str, gold: &GoldSpan, issued: Option<&str>) -> Outcome {
    match issued {
        None => Outcome::Blocked,
        Some(issued) if leaked(text, gold, issued) => Outcome::Leaked,
        Some(_) => Outcome::Masked,
    }
}

pub(crate) fn gate_hides(text: &str, gold: &GoldSpan, issued: Option<&str>) -> bool {
    outcome(text, gold, issued) == Outcome::Masked
}
