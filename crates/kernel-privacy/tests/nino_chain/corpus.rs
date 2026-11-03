//! The seeded corpus: 1,800 documents of NI chains mixed with the other
//! classes.

use super::helpers::{number, BREAKS, KINDS, LETTERS, PAIRS, PREFIXES};

/// The seeded differential: 1,800 documents of a chain of two to five National
/// Insurance numbers in shapes of their own with digits of their own, mixed
/// with the other classes (IBAN, phone, e-mail, card, health value, NIR, key,
/// password, an address line) and prose, joined by every break the normaliser
/// folds.
pub(crate) fn documents() -> Vec<String> {
    let mut rng = Rng(0x4e49_4e4f_4348_4149);
    let mut out = Vec::new();
    for _ in 0..1_800 {
        let count = 2 + rng.next() % 4;
        // Each number of a document takes the next triple, so no two of its
        // numbers are the same value (five numbers, eight triples).
        let first = rng.next() as usize;
        let mut doc = String::new();
        for at in 0..count {
            if at > 0 {
                doc.push_str(rng.pick(BREAKS));
            }
            if at > 0 && rng.next().is_multiple_of(5) {
                doc.push_str(rng.pick(OTHERS));
                doc.push_str(rng.pick(BREAKS));
            }
            let suffix = match rng.next() % 3 {
                0 => None,
                _ => Some(LETTERS[(rng.next() % 4) as usize]),
            };
            doc.push_str(&number(
                (rng.next() % KINDS as u64) as usize,
                PREFIXES[(rng.next() % PREFIXES.len() as u64) as usize],
                (first + at as usize) % PAIRS.len(),
                suffix,
            ));
        }
        if rng.next().is_multiple_of(3) {
            doc.push_str(rng.pick(BREAKS));
            doc.push_str(rng.pick(OTHERS));
        }
        out.push(doc);
    }
    out
}

/// The other classes a chain sits next to, so the differential is not only a
/// chain of numbers.
const OTHERS: &[&str] = &[
    "IBAN GB29 NWBK 6016 1331 9268 19",
    "IBAN FR76 3000 6000 0112 3456 7890 189",
    "call +44 20 7946 0958 today",
    "mail alice.smith@example.org",
    "blood type A+",
    "health plan number 7KL2-QW9-PX41",
    "card 4111 1111 1111 1111",
    "NIR 1 84 12 76 451 089 46",
    "key AKIAIOSFODNN7EXAMPLE",
    "password: Sunflower2025",
    "Total due 42.00",
    "see attached.",
    "Dear customer,",
    "12 Baker Street",
    // Letters and digits a suffix letter may be glued to without opening a
    // number, so a chain that ends next to one keeps what main masked.
    "Cat sat",
    "Xray",
    "B7 ward",
    "dog",
];

/// A xorshift64, so the corpus is the same text on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<'a>(&mut self, list: &'a [&'a str]) -> &'a str {
        list[(self.next() % list.len() as u64) as usize]
    }
}
