//! The invented keys and the exact reader that says which bytes a gate
//! masked.

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("../data/norm1_cases.rs");
}
use norm1::exact_ranges;
pub(crate) use norm1::{covered, issue, MODES};

/// One mode's record of `input`, read by the shared exact reader:
/// `start-end,` ranges; `!` a refusal; `?` an output that does not read back.
pub(crate) fn exact(mode: PrivacyMode, input: &str) -> String {
    let Some((output, minted)) = issue(mode, input) else {
        return "!".into();
    };
    exact_ranges(mode, input, &output, &minted).map_or("?".into(), |r| {
        r.iter().map(|(s, e)| format!("{s}-{e},")).collect()
    })
}

pub(crate) fn parse(record: &str) -> Vec<(usize, usize)> {
    record
        .split(',')
        .filter_map(|r| r.split_once('-'))
        .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
        .collect()
}

/// A xorshift64, so the corpus is the same text on every machine.
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub(crate) fn pick<'a>(&mut self, list: &[&'a str]) -> &'a str {
        list[(self.next() % list.len() as u64) as usize]
    }
}

/// `n` invented key characters, `_` and `-` included, seeded by `seed`.
fn body(seed: u64, n: usize) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    (0..n)
        .map(|_| char::from(alphabet[(rng.next() % 64) as usize]))
        .collect()
}

/// `n` invented ASCII letters and digits, with a `7Q` in the middle.
pub(crate) fn alnum(seed: u64, n: usize) -> String {
    let mut out: String = body(seed, n * 4)
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .chain("x9K".chars().cycle())
        .take(n - 2)
        .collect();
    out.insert_str(n / 2 - 1, "7Q");
    out
}

/// One invented key per prefix of the family: `(prefix, key)`.
pub(crate) fn keys(i: u64) -> Vec<(&'static str, String)> {
    let digits = format!("{:010}", i.wrapping_mul(0x2545_F491) % 10_000_000_000);
    let slack = |kind: &str, n| format!("xox{kind}-1{digits}-2{digits}-{}", alnum(i, n));
    vec![
        ("sk-", format!("s{}-{}", "k", alnum(i, 48))),
        ("sk-proj-", format!("sk-{}-{}", "proj", alnum(i + 1, 64))),
        ("sk-proj-", format!("sk-{}-{}A1b", "proj", body(i + 2, 120))),
        (
            "sk-ant-",
            format!("sk-{}-api03-{}AA", "ant", alnum(i + 3, 93)),
        ),
        ("ghp_", format!("gh{}_{}", "p", alnum(i + 4, 36))),
        ("gho_", format!("gh{}_{}", "o", alnum(i + 5, 36))),
        ("ghs_", format!("gh{}_{}", "s", alnum(i + 6, 36))),
        (
            "github_pat_",
            format!("github{}_{}_{}", "_pat", alnum(i + 7, 22), alnum(i + 8, 59)),
        ),
        ("xoxb-", slack("b", 24)),
        ("xoxp-", slack("p", 32)),
        (
            "AKIA",
            format!("AK{}{}", "IA", alnum(i + 9, 16).to_uppercase()),
        ),
        (
            "ASIA",
            format!("AS{}{}", "IA", alnum(i + 10, 16).to_uppercase()),
        ),
        ("AIza", format!("AI{}Sy{}", "za", alnum(i + 11, 33))),
        ("GOCSPX-", format!("GOC{}-{}", "SPX", alnum(i + 12, 28))),
        ("ya29.", format!("ya{}.a0{}", "29", alnum(i + 13, 60))),
        ("sk_live_", format!("sk{}_{}", "_live", alnum(i + 14, 24))),
        ("rk_live_", format!("rk{}_{}", "_live", alnum(i + 15, 24))),
        ("glpat-", format!("glp{}-{}", "at", alnum(i + 16, 20))),
        ("npm_", format!("np{}_{}", "m", alnum(i + 17, 36))),
        ("sl.", format!("s{}.{}", "l", alnum(i + 18, 130))),
        (
            "eyJ",
            format!(
                "ey{}{}.ey{}{}.{}",
                "J",
                alnum(i + 19, 30),
                "J",
                alnum(i + 20, 40),
                alnum(i + 21, 43)
            ),
        ),
    ]
}

/// `n` characters drawn uniformly from `alphabet`.
pub(crate) fn draw(rng: &mut Rng, alphabet: &[u8], n: usize) -> String {
    (0..n)
        .map(|_| char::from(alphabet[(rng.next() % alphabet.len() as u64) as usize]))
        .collect()
}

pub(crate) const BASE62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub(crate) const BASE64URL: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
pub(crate) const HEX: &[u8] = b"0123456789abcdef";

/// `output` with each minted token replaced by its surface.
pub(crate) fn restore(output: &str, minted: &[(String, String)]) -> String {
    let mut restored = output.to_string();
    for (token, surface) in minted {
        restored = restored.replace(&format!("⟦{token}⟧"), surface);
    }
    restored
}
