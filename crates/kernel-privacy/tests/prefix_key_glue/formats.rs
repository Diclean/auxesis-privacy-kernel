//! The issuers' exact formats of the `sk-` and `sl.` family, glued after
//! letters and digits.

use super::helpers::{covered, draw, exact, parse, Rng, BASE62, BASE64URL, HEX, MODES};

/// The issuers' exact formats of the `sk-` and `sl.` family: a name, and an
/// invented key in that format, uniformly random, built at runtime.
const FORMATS: &[&str] = &[
    "openai-legacy-48",
    "openai-legacy-marker",
    "deepseek-32hex",
    "openrouter-64hex",
    "openai-proj",
    "openai-svcacct",
    "openai-admin",
    "anthropic-api03",
    "anthropic-admin01",
    "dropbox-sl",
    "dropbox-sl-u",
];

fn format_key(format: &str, rng: &mut Rng) -> String {
    let marker = ["T3Blbk", "FJ"].concat();
    let sk = |rest: String| format!("s{}-{rest}", "k");
    let long = |rng: &mut Rng, sub: &str| {
        let n = 140 + (rng.next() % 40) as usize;
        let mut tail = draw(rng, BASE64URL, n);
        tail.insert_str(n / 2, &marker);
        sk(format!("{sub}-{tail}"))
    };
    match format {
        "openai-legacy-48" => sk(draw(rng, BASE62, 48)),
        "openai-legacy-marker" => sk(draw(rng, BASE62, 20) + &marker + &draw(rng, BASE62, 20)),
        "deepseek-32hex" => sk(draw(rng, HEX, 32)),
        "openrouter-64hex" => sk(format!("or-{}-{}", "v1", draw(rng, HEX, 64))),
        "openai-proj" => long(rng, "proj"),
        "openai-svcacct" => long(rng, "svcacct"),
        "openai-admin" => long(rng, "admin"),
        "anthropic-api03" => sk(format!("ant-{}-{}AA", "api03", draw(rng, BASE64URL, 93))),
        "anthropic-admin01" => sk(format!("ant-{}-{}AA", "admin01", draw(rng, BASE64URL, 93))),
        "dropbox-sl" => format!("s{}.{}", "l", draw(rng, BASE64URL, 135)),
        _ => format!("s{}.u.{}", "l", draw(rng, BASE64URL, 140)),
    }
}

/// What a format key is glued after: letters and digits only.
const FORMAT_GLUES: &[&str] = &[
    "note", "key", "x", "Token", "2024", "7", "A", "z9", "apiKey", "OPENAI", "id0",
];

/// Where a format key sits.
const FORMAT_FRAMES: &[&str] = &[
    "cfg: {}",
    "The key is {} for prod.",
    "first line\n{}\nnext line",
    "{}",
    "cfg: {}-",
    "cfg: {}_",
    "The key is {}-prod here.",
    "The key is {}_old here.",
    "high-risk-\n{} ok",
];

/// `(format, text, key start, key end)`: `per` keys of every format, each glued
/// after a letter or digit, in a frame, from a fixed seed.
pub(crate) fn format_positives(per: usize, seed: u64) -> Vec<(&'static str, String, usize, usize)> {
    let mut rng = Rng(seed | 1);
    let mut out = Vec::new();
    for format in FORMATS {
        for i in 0..per {
            let key = format_key(format, &mut rng);
            let glue = FORMAT_GLUES[i % FORMAT_GLUES.len()];
            let frame = FORMAT_FRAMES[(i / FORMAT_GLUES.len()) % FORMAT_FRAMES.len()];
            let (head, tail) = frame.split_once("{}").expect("frame");
            let start = head.len() + glue.len();
            out.push((
                *format,
                format!("{head}{glue}{key}{tail}"),
                start,
                start + key.len(),
            ));
        }
    }
    out
}

/// Misses per format and mode `[Private, Open]`, read by the exact reader.
fn format_misses(per: usize, seed: u64) -> Vec<(&'static str, [usize; 2], String)> {
    let mut out: Vec<(&'static str, [usize; 2], String)> = FORMATS
        .iter()
        .map(|f| (*f, [0, 0], String::new()))
        .collect();
    for (format, text, start, end) in format_positives(per, seed) {
        let row = out.iter_mut().find(|row| row.0 == format).expect("format");
        for (index, mode) in MODES.into_iter().enumerate() {
            let now = exact(mode, &text);
            if !covered(&parse(&now), start, end) {
                row.1[index] += 1;
                if row.2.is_empty() {
                    row.2 = format!("{mode:?} {text:?}: {now}");
                }
            }
        }
    }
    out
}

fn assert_no_format_misses(per: usize, seed: u64) {
    let rows = format_misses(per, seed);
    for (format, misses, first) in &rows {
        eprintln!("{format}: {per} keys, misses Private/Open {misses:?} {first}");
    }
    let missed: Vec<_> = rows.iter().filter(|row| row.1 != [0, 0]).collect();
    assert!(missed.is_empty(), "{missed:#?}");
}

/// Every exact format, glued after letters and digits: 0 misses in both modes.
#[test]
fn glued_exact_formats_are_hidden_in_both_modes() {
    assert_no_format_misses(220, 0x464F_524D_4154_5331);
}

/// The 20,000-keys-per-format run (release).
#[test]
#[ignore = "slow: cargo test --release --test prefix_key_glue -- --ignored formats_20k --nocapture"]
fn glued_exact_formats_20k() {
    assert_no_format_misses(20_000, 0x3230_4B5F_4B45_5953);
}
