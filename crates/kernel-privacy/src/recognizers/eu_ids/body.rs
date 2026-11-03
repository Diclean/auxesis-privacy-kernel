//! The body the EU rules read: its digit runs, the runs a line break joins and
//! the run without its folded breaks.

use crate::normalize::{numeric_runs, NormalizedText};

use super::Body;

/// The most digits a wrapped value holds: a sub-chain of break-joined runs is
/// read up to this many digits, so the scan stays linear.
const CHAIN_DIGITS_MAX: usize = 13;

/// The digit runs of the body, with the runs a line break separates joined
/// into one run more.
///
/// A run of separators that holds a line break is one separator, so a value
/// wrapped after a hyphen or a dot stays one value. The joined run is a run
/// more: the runs it joins stay, so no value is ever lost.
pub(super) fn grouped_runs(
    body: &str,
    original: &str,
    view: &NormalizedText,
) -> Vec<(usize, usize)> {
    let runs = numeric_runs(body);
    // The end of the chain of every run: the runs a break-holding run of
    // separators joins, and the ones that chain joins in turn. One pass, so
    // the scan stays linear.
    let mut chain_end = vec![0usize; runs.len()];
    for index in (0..runs.len()).rev() {
        chain_end[index] = if index + 1 < runs.len()
            && separated_by_break(body, original, view, runs[index].1, runs[index + 1].0)
        {
            chain_end[index + 1]
        } else {
            index
        };
    }
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(runs.len() * 2);
    for (index, &(start, end)) in runs.iter().enumerate() {
        out.push((start, end));
        // The chain of the run, when the run starts one: the runs a
        // break-holding run of separators joins are one value. One run per
        // chain, so the joined runs stay disjoint and the scan stays linear.
        let last = chain_end[index];
        let starts_chain = index == 0 || chain_end[index - 1] < index;
        if last > index && starts_chain {
            out.push((start, runs[last].1));
        }
        // The shorter chains from the run: a wrapped value followed by more
        // break-joined runs is one value too. Each run adds a digit at least,
        // so a run starts at most [`CHAIN_DIGITS_MAX`] chains.
        let mut digits = ascii_digit_count(&body[start..end]);
        for next in index + 1..=last {
            digits += ascii_digit_count(&body[runs[next].0..runs[next].1]);
            if digits > CHAIN_DIGITS_MAX {
                break;
            }
            // The whole chain is already in.
            if !(starts_chain && next == last) {
                out.push((start, runs[next].1));
            }
        }
    }
    out
}

/// The ASCII digits of `text`.
fn ascii_digit_count(text: &str) -> usize {
    text.bytes().filter(u8::is_ascii_digit).count()
}

/// Whether two runs are separated by a run of separators that holds a line
/// break: the gap holds nothing but separators, and the original bytes of the
/// gap hold a break.
fn separated_by_break(
    body: &str,
    original: &str,
    view: &NormalizedText,
    from: usize,
    to: usize,
) -> bool {
    if from >= to {
        return false;
    }
    let Some(gap) = body.get(from..to) else {
        return false;
    };
    if !gap
        .bytes()
        .all(|byte| matches!(byte, b' ' | b'-' | b'.' | b'/'))
    {
        return false;
    }
    let Some((start, end)) = view.to_original(from, to) else {
        return false;
    };
    original
        .get(start..end)
        .is_some_and(|bytes| bytes.contains(['\n', '\r']))
}

/// The run `start..end` of the body without its runs of separators that hold
/// a line break. A run of the body is ASCII: digits and separators.
pub(super) fn unwrapped(body: &Body, start: usize, end: usize) -> String {
    let bytes = body.text.as_bytes();
    let mut out = String::with_capacity(end - start);
    let mut at = start;
    while at < end {
        let gap = (at..end)
            .find(|&next| bytes[next].is_ascii_digit())
            .unwrap_or(end);
        if gap == at {
            out.push(char::from(bytes[at]));
            at += 1;
            continue;
        }
        if !body.holds_break(at, gap) {
            out.push_str(&body.text[at..gap]);
        }
        at = gap;
    }
    out
}
