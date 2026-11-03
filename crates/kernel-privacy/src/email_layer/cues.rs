//! The phrase lists a mail rule reads: greetings, closings, headers, speech
//! verbs, titles and the discourse words that are never names.

use std::collections::HashSet;

use crate::public_terms::fold;

/// Query parameter names that carry an address or a name in a tracking link.
pub(super) const TRACKING_KEYS: &[&str] = &[
    "e",
    "email",
    "u",
    "uid",
    "name",
    "recipient",
    "mail",
    "to",
    "nom",
    "naam",
];

/// Greeting words, longest first so a multi-word greeting wins.
///
/// Matching is case-insensitive, so a lower-case greeting works too; the entries
/// below add the colloquial forms of the six corpus languages.
pub(super) const GREETINGS: &[&str] = &[
    "здравствуйте",
    "здравствуй",
    "добрый день",
    "добрый вечер",
    "السلام عليكم",
    "guten tag",
    "goeie môre",
    "goeie more",
    "bonjour",
    "bonsoir",
    "coucou",
    "salut",
    "hello",
    "hallo",
    "haai",
    "beste",
    "liewe",
    "goeie",
    "geachte",
    "kedves",
    "sziasztok",
    "привет",
    "مرحبا",
    "السلام",
    "عزيزي",
    "عزيزتي",
    "سلام",
    "هلا",
    "واخا",
    "أهلا",
    "helló",
    "szia",
    "liebe",
    "dear",
    "hey",
    "hi",
    "üdv",
    "您好",
    "你好",
    "哈囉",
    "哈罗",
    "嗨",
];

/// Closing words that end a sign-off line, longest first.
///
/// A closing line opens a signature block, so the name below it always stays
/// masked. The list carries the common forms of the six corpus languages plus
/// the German (`Mit freundlichen Grüßen`, `Viele Grüße`, `Liebe Grüße`), Chinese
/// (`此致敬礼`, `此致`, `敬礼`, `祝好`, `顺祝商祺`), Dutch/Afrikaans
/// (`Met vriendelike groete`) and Hungarian (`Üdvözlettel`, `Tisztelettel`)
/// closings, with the ASCII `Gruessen`/`Gruesse`/`Grusse` variants of the
/// German ones.
pub(super) const CLOSINGS: &[&str] = &[
    "mit freundlichen grüßen",
    "mit freundlichen gruessen",
    "mit freundlichen gruesse",
    "met vriendelike groete",
    "vriendelike groete",
    "herzliche grüße",
    "herzliche gruesse",
    "freundliche grüße",
    "freundliche gruesse",
    "bien cordialement",
    "bien à vous",
    "szívélyes üdvözlettel",
    "с наилучшими пожеланиями",
    "dankie vir die hulp",
    "beste grüße",
    "beste gruesse",
    "viele grüße",
    "viele gruesse",
    "liebe grüße",
    "liebe gruesse",
    "liebe grusse",
    "cordialement",
    "amicalement",
    "kind regards",
    "best regards",
    "thanks a lot",
    "many thanks",
    "üdvözlettel",
    "tisztelettel",
    "с уважением",
    "всего доброго",
    "مع تحياتي",
    "مع التحية",
    "شكرا جزيلا",
    "此致敬礼",
    "顺祝商祺",
    "regards",
    "dankie",
    "groete",
    "bisous",
    "bises",
    "thanks",
    "cheers",
    "此致",
    "敬礼",
    "祝好",
    "تحياتي",
    "شكرا",
    "best",
    "üdv",
];

/// Words that address the reader right before a name (`merci Jules`,
/// `thanks Mila`, `köszi Anna`). A name directly after one of these is in an
/// address position (the thanks check of [`super::signals::in_vocative_or_address`]). The list
/// is folded (lowercase, marks dropped) because the lookup folds the text.
pub(super) const ADDRESS_THANKS: &[&str] = &[
    "thank you",
    "thanks",
    "spasibo",
    "bedankt",
    "dankie",
    "koszonom",
    "koszi",
    "merci",
    "danke",
    "谢谢",
    "شكرا",
];

/// Marks that close a greeting or thanks clause: a line end, then the ASCII,
/// Arabic and full-width clause punctuation (see [`super::signals::closes_address_clause`]).
pub(super) const CLAUSE_MARKS: &str = "\r\n,!:;.?\u{060C}，！：；。？";

/// Verbs that introduce a quoted reply.
pub(super) const REPLY_VERBS: &[&str] = &[
    "wrote:",
    "a écrit",
    "geskryf",
    "írta",
    "написал",
    "написала",
    "كتب",
];

/// Sender and recipient header keys, already lowercased and without the colon.
///
/// A name on any of these lines is signature/header context and always stays:
/// `From`, `To`, `Cc`, the French `De`, the Dutch `Van`, the German `Von`, the
/// Russian `От`, the Hungarian `Feladó`, the Arabic `من` and the Chinese
/// `发件人` / `收件人`.
pub(super) const SENDER_KEYS: &[&str] = &[
    "from",
    "to",
    "cc",
    "de",
    "van",
    "von",
    "от",
    "feladó",
    "felado",
    "من",
    "sender",
    "发件人",
    "收件人",
];

/// Subject header keys, lowercased and without the colon. A name line directly
/// follows one of these in a forwarded or reply body.
pub(super) const SUBJECT_KEYS: &[&str] = &[
    "subject",
    "objet",
    "betreff",
    "tárgy",
    "targy",
    "тема",
    "onderwerp",
    "الموضوع",
];

/// Verbs that introduce a spoken clause, with whether the speaker is named
/// before the verb (`X said`) or after it (`قال X`), longest first.
pub(super) const SPEECH_VERBS: &[(&str, bool)] = &[
    ("azt mondta", true),
    ("het gesê", true),
    ("het gese", true),
    ("a dit", true),
    ("сказала", true),
    ("сказал", true),
    ("said", true),
    ("says", true),
    ("قال", false),
];

/// Honorifics and roles that a rule must not seed as a name on their own.
pub(super) const TITLES: &[&str] = &[
    "dr",
    "mr",
    "mrs",
    "ms",
    "mme",
    "mlle",
    "prof",
    "sir",
    "madame",
    "monsieur",
    "herr",
    "frau",
    "mevrouw",
    "meneer",
    "úr",
    "asszony",
    "г-н",
    "г-жа",
    "سيد",
    "سيدة",
    "دكتور",
];

/// Discourse words that a capitalized opening (`Yes, …`, `Note, …`) would
/// otherwise seed as a name.
pub(super) const DISCOURSE_WORDS: &[&str] = &[
    "yes",
    "no",
    "ok",
    "okay",
    "well",
    "sure",
    "note",
    "notes",
    "update",
    "updates",
    "news",
    "fyi",
    "btw",
    "important",
    "urgent",
    "reminder",
    "info",
    "all",
    "team",
    "everyone",
    "everybody",
    "folks",
    "guys",
    "colleagues",
    "re",
    "fwd",
    "objet",
    "subject",
    "message",
];

/// Folded words that open or close a mail or name a role or a discourse move;
/// none of them is a name, whatever its case. The phrases are split into words
/// and folded, so `Üdvözlettel`, `С уважением` and `Здравствуйте` are all caught.
pub(super) static RULE_WORDS: std::sync::LazyLock<HashSet<String>> =
    std::sync::LazyLock::new(|| {
        GREETINGS
            .iter()
            .chain(CLOSINGS.iter())
            .chain(TITLES.iter())
            .chain(DISCOURSE_WORDS.iter())
            .flat_map(|phrase| phrase.split(|ch: char| !ch.is_alphanumeric()))
            .filter(|word| !word.is_empty())
            .map(fold)
            .collect()
    });

/// Courtesy and discourse interjections that a capitalized rule hit would
/// otherwise seed (`Merci, …`, `Спасибо, …`, `Köszönöm, …`). They are not names,
/// whatever their case.
pub(super) const COURTESY_WORDS: &[&str] = &[
    "merci",
    "amities",
    "amitiés",
    "cordialement",
    "спасибо",
    "пожалуйста",
    "köszönöm",
    "koszonom",
    "kérem",
    "kerem",
    "dankie",
    "asseblief",
    "eerlikwaar",
    "شكرا",
    "عفوا",
    "تحياتي",
    // Discourse adverbs and one-word headers a rule would otherwise name as a
    // person (`fontos`, `важно`, `отправлено`, `elküldve`).
    "fontos",
    "важно",
    "отправлено",
    "elkuldve",
    "elküldve",
    "hier",
    // Discourse and interjection words seen opening a line before a comma.
    "rendben",
    "хорошо",
    "ок",
    "köszi",
    "koszi",
    "szépen",
    "szepen",
    "salam",
    "dringend",
    "chère",
    "chere",
    "cher",
    "честно",
    "говоря",
    "بصراحة",
    "őszintén",
    "oszinten",
    "szólva",
    "szolva",
];

/// Words that open a question or a request, never a vocative: a line that
/// starts with one, then a comma later, is a sentence, not an address
/// (`How many unread mails do I have, and who sent the newest one?`).
///
/// Closed and functional like [`super::function_words::FUNCTION_WORDS`]; it holds no first name
/// (`Will`, `Mark`, `Rose`, `Maxime` still open a vocative).
pub(super) const QUESTION_OPENERS: &[&str] = &[
    "how",
    "why",
    "can",
    "would",
    "please",
    "show",
    "tell",
    "give",
    "list",
    "check",
    "find",
    "send",
    "open",
    "read",
    "summarise",
    "summarize",
    "comment",
    "pourquoi",
    "combien",
    "quel",
    "quels",
    "quelle",
    "quelles",
    "quand",
    "est-ce",
    "peux-tu",
    "pouvez-vous",
    "peux",
    "pouvez",
    "où",
    "ou",
    "qui",
    "que",
    "quoi",
    "dis-moi",
    "montre-moi",
    "donne-moi",
    "je",
    "j",
    "il",
    "elle",
    "on",
    "nous",
    "vous",
    "il y a",
];
