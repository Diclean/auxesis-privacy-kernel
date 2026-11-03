//! The seeded corpus: the look-alikes, the other classes and the documents
//! they sit in.

use super::formats::format_positives;
use super::helpers::{keys, Rng};
use super::prefixes::{positives, FRAMES};

pub(crate) const FIXTURE: &str = include_str!("../data/prefix_key_glue_main.txt");

/// Words that hold a prefix, `¦`-separated: none is a key. `{camel}`, `{uuid}`,
/// `{UUID}` and `{hex}` are filled at runtime by [`lookalikes`].
const LOOKALIKES: &str = "desk-top¦risk-free¦task-force¦kiosk-mode¦whisk-in¦Ask-me¦\
    desk-Booking-System-v12-Release-Notes-2024¦risk-assessment-framework-2024-Q3-report¦\
    task-{camel}¦flask-SQLAlchemy-extension-v3¦\
    disk-{uuid}¦task-{hex}¦disk-{id48}¦task-{camel48}¦desk-{camel48}-v2¦\
    ta{sk}-proj-quarterly-planning-review-for-the-sales-team-and-the-board-2024-final-v3¦\
    ri{sk}-admin-escalation-matrix-for-regional-offices-and-partners-2024-q3-draft¦\
    Basel.u.Office¦consul.a.b¦tasksl.u.v2¦ri{sk}-or-v1-review¦\
    risk-{UUID}¦Asia¦ASIA-Pacific¦Southeast Asia¦Slovakia¦\
    eyJustice¦eyJ¦heyJude¦Aizawa¦AIzawa¦ya29 model¦npm_install¦ghost_town¦ghp_ prefix¦\
    sk_live_ docs¦glpat- token¦GOCSPX- secret¦xoxb- tokens¦AKIA prefix¦Russl.Co¦tasksl.v2¦\
    basket-of-goods¦brisk-walk¦obelisk-tower";

/// Business sentences the look-alikes sit in, `¦`-separated.
const SENTENCES: &str = "Please book a {} for the Monday meeting.¦The {} plan was approved.¦\
    See ticket {} before Friday.¦Our {} budget is 12,500 EUR.¦{} — notes from the call.¦\
    Revenue in {} grew 8% this quarter.¦Attach the {} file to the invoice.¦\
    The team moved {} to the next sprint.¦Kind regards, {} team";

/// 1,000+ business and prose texts with prefix-like words, no key.
fn lookalikes() -> String {
    let uuid = ["3fa85f64", "5717", "4562", "b3fc", "2c963f66afa6"].join("-");
    let camel = [
        "calculate",
        "Total",
        "Amount",
        "For",
        "User",
        "Account",
        "Balance",
        "In",
        "Euros",
        "2024",
    ]
    .concat();
    let camel48 = camel.trim_end_matches("2024");
    assert_eq!(camel48.len(), 48);
    LOOKALIKES
        .replace("{sk}", "sk")
        .replace("{camel48}", camel48)
        .replace("{id48}", &["Xq7", "Lm2", "Rt9", "Kd4"].concat().repeat(4))
        .replace("{camel}", &camel)
        .replace("{uuid}", &uuid)
        .replace("{UUID}", &uuid.to_uppercase())
        .replace(
            "{hex}",
            &["7f3a9c1e", "2b4d6f80", "a1b2c3d4", "e5f60718"].concat(),
        )
}

pub(crate) fn negatives() -> Vec<String> {
    let all = lookalikes();
    let words: Vec<&str> = all.split('¦').collect();
    let sentences: Vec<&str> = SENTENCES.split('¦').collect();
    let mut rng = Rng(0x4C4F_4F4B_414C_494B);
    let mut out = Vec::new();
    for word in &words {
        for sentence in &sentences {
            out.push(sentence.replace("{}", word));
        }
    }
    while out.len() < 1_250 {
        let glue = rng.pick(&["", "", " ", "\n", "-", "_"]);
        let text = format!(
            "{} {}{glue}{}",
            rng.pick(&sentences).replace("{}", rng.pick(&words)),
            rng.pick(&["Re:", "Note", "Q3", "item7", ""]),
            rng.pick(&words)
        );
        out.push(text);
    }
    out
}

/// Values of the other classes and prose, `¦`-separated.
const OTHERS: &str = "IBAN FR76 3000 6000 0112 3456 7890 189¦GB82 WEST 1234 5698 7654 32¦\
    card 4111 1111 1111 1111 exp 09/29¦NI number QQ 12 34 56 C¦AB123456C¦SSN 512-45-8873¦\
    she has type 2 diabetes¦lena.ortiz@example.org¦call +44 20 7946 0958¦\
    see https://example.test/login¦Thanks for the update.¦risk-free desk-top¦Asia trip¦\
    api_key: ¦password=";

/// The seeded corpus: 1,600 documents of two to five parts (a key glued or not,
/// another class's value, or prose), joined by a break, glue or a sentence end.
fn seeded() -> Vec<String> {
    let mut rng = Rng(0x534B_5052_4F4A_474C);
    let others: Vec<&str> = OTHERS.split('¦').collect();
    let glues = [
        "note", "Key", "x", "2024", "7", "_", "my_", "", " ", "-", "\n", "日本",
    ];
    let mut out = Vec::new();
    for i in 0..1_600u64 {
        let mut parts: Vec<String> = Vec::new();
        for _ in 0..2 + rng.next() % 4 {
            let part = match rng.next() % 3 {
                0 => {
                    let all = keys(i * 7 + rng.next() % 5);
                    let key = &all[(rng.next() % all.len() as u64) as usize].1;
                    let frame = FRAMES[(rng.next() % FRAMES.len() as u64) as usize];
                    frame.replace("{}", &format!("{}{key}", rng.pick(&glues)))
                }
                1 => rng.pick(&others).to_string(),
                _ => rng
                    .pick(&["Hello", "Notes:", "x", "task-force", "eyJustice"])
                    .to_string(),
            };
            if !parts.contains(&part) {
                parts.push(part);
            }
        }
        let joint = rng.pick(&["\n", "\r\n", "\t", " ", "", ". "]);
        out.push(parts.join(joint));
    }
    out
}

pub(crate) fn inputs() -> Vec<String> {
    let mut out = seeded();
    out.extend(negatives());
    out.extend(positives().into_iter().map(|(text, _, _)| text));
    // 99 = 11 glues x 9 frames: every frame of every format.
    out.extend(
        format_positives(99, 0x4449_4646_4552_454E)
            .into_iter()
            .map(|(_, text, _, _)| text),
    );
    out
}

/// The input count and an FNV-1a hash of every input.
pub(crate) fn header(inputs: &[String]) -> String {
    let bytes = inputs.iter().flat_map(|text| text.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", inputs.len())
}
