//! The table primitives: bars, rates and row formatting.

use crate::tiers::TierTally;

/// The bars of the table in `README.md`, in hundredths of a percent where a
/// rate is compared.
///
/// Tier C covers the prohibited classes and Tier H the model-emitted kinds that
/// are not names, so neither bar can be reached by averaging in a class the
/// product does not claim to hide. A bar with nothing behind it prints
/// `n/a (n = 0)`, never a pass.
pub(crate) const BAR_C_HUNDREDTHS: u64 = 9950; // >= 99.5 %, the prohibited classes

pub(crate) const BAR_H_STANDARD_HUNDREDTHS: u64 = 9500; // >= 95 %

pub(crate) const BAR_H_DEEP_HUNDREDTHS: u64 = 9800; // >= 98 %

pub(crate) const BAR_TRAP_FP: u64 = 40; // <= 40

pub(crate) const BAR_LATENCY_STANDARD_MS: u64 = 150; // <= 150 ms

pub(crate) const BAR_LATENCY_DEEP_MS: u64 = 400; // <= 400 ms

pub(crate) const BAR_PEAK_MEMORY_MB: u64 = 1024; // <= 1 GB

/// `caught / total` in hundredths of a percent, truncated, or `None` when the
/// tally is empty: it has no rate and used to read `100 %`.
pub(crate) fn hundredths(caught: u64, total: u64) -> Option<u64> {
    (total > 0).then(|| caught.saturating_mul(10000) / total)
}

/// What a cell shows when nothing was measured.
pub(crate) const NO_RATE: &str = "n/a (n = 0)";

/// `xx.xx %`, or [`NO_RATE`] when the tally is empty.
pub(crate) fn rate_cell(caught: u64, total: u64) -> String {
    hundredths(caught, total).map_or_else(|| NO_RATE.to_string(), pct)
}

/// Render hundredths of a percent as `xx.xx %` without rounding up.
pub(crate) fn pct(hundredths: u64) -> String {
    format!("{}.{:02} %", hundredths / 100, hundredths % 100)
}

/// `MET` when the measured rate reaches the bar, `MISSED` otherwise.
pub(crate) fn met(hundredths: u64, bar: u64) -> &'static str {
    if hundredths >= bar {
        "MET"
    } else {
        "MISSED"
    }
}

/// One table row, in the exact column shape of the table in `README.md`.
pub(crate) fn row_line(measure: &str, value: &str, bar: &str, status: &str) -> String {
    format!("{measure:<42}{value:<10}{bar:<11}{status}")
}

pub(crate) fn print_row(measure: &str, value: &str, bar: &str, status: &str) {
    println!("{}", row_line(measure, value, bar, status));
}

/// A measured row and its bar. The bar is decided only on a tally that holds
/// something: an empty one prints `n/a (n = 0)`, never a pass. The counts
/// always print, so a rate is never read without its denominator.
pub(crate) fn measured_line(measure: &str, tally: &TierTally, bar: Option<(&str, u64)>) -> String {
    let text = bar.map_or("no bar", |(t, _)| t);
    let Some(value) = tally.hundredths() else {
        return row_line(measure, NO_RATE, text, "NOT MEASURED");
    };
    let status = match bar {
        Some((_, at)) => met(value, at),
        None => "MEASURED",
    };
    let status = format!("{status} {}/{}", tally.caught, tally.total);
    row_line(measure, &pct(value), text, &status)
}

pub(crate) fn measured_row(measure: &str, tally: &TierTally, bar: Option<(&str, u64)>) {
    println!("{}", measured_line(measure, tally, bar));
}

/// The Tier C bar, as the rows print it.
pub(crate) const BAR_C: Option<(&str, u64)> = Some((">= 99.5 %", BAR_C_HUNDREDTHS));
