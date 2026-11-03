//! Header, calendar, role-mailbox and structural-word lists, plus birth-date
//! cues.

use std::collections::HashSet;

use crate::public_terms::fold;

use super::cues::{COURTESY_WORDS, RULE_WORDS};
use super::function_words::FUNCTION_WORDS;

/// Header labels of the six corpus languages. A sender or subject header must
/// never seed its own label as a name (`De :`, `Objet :`, `From:`, `Тема:`).
const HEADER_LABELS: &[&str] = &[
    "from",
    "to",
    "cc",
    "cco",
    "bcc",
    "reply-to",
    "sender",
    "subject",
    "date",
    "datum",
    "dátum",
    "elkuldve",
    "elküldve",
    "gestuur",
    "importance",
    "priority",
    "sent",
    "de",
    "a",
    "à",
    "objet",
    "envoye",
    "envoyé",
    "priorite",
    "priorité",
    "van",
    "aan",
    "onderwerp",
    "verzonden",
    "gesendet",
    "felado",
    "feladó",
    "cimzett",
    "címzett",
    "targy",
    "tárgy",
    "от",
    "кому",
    "тема",
    "дата",
    "من",
    "الى",
    "إلى",
    "التاريخ",
    "الموضوع",
];

/// Weekdays and months of the six corpus languages, so a date line or a
/// forwarded header never names one as a person.
const CALENDAR_WORDS: &[&str] = &[
    // English.
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    // French.
    "lundi",
    "mardi",
    "mercredi",
    "jeudi",
    "vendredi",
    "samedi",
    "dimanche",
    "janvier",
    "fevrier",
    "février",
    "mars",
    "avril",
    "mai",
    "juin",
    "juillet",
    "aout",
    "août",
    "septembre",
    "octobre",
    "novembre",
    "decembre",
    "décembre",
    // Afrikaans.
    "maandag",
    "dinsdag",
    "woensdag",
    "donderdag",
    "vrydag",
    "saterdag",
    "sondag",
    "januarie",
    "februarie",
    "maart",
    "april",
    "mei",
    "junie",
    "julie",
    "augustus",
    "september",
    "oktober",
    "november",
    "desember",
    // Hungarian.
    "hetfo",
    "hétfő",
    "kedd",
    "szerda",
    "csutortok",
    "csütörtök",
    "pentek",
    "péntek",
    "szombat",
    "vasarnap",
    "vasárnap",
    "januar",
    "január",
    "februar",
    "február",
    "marcius",
    "március",
    "aprilis",
    "április",
    "majus",
    "május",
    "junius",
    "június",
    "julius",
    "július",
    "augusztus",
    "szeptember",
    "oktober",
    "október",
    "november",
    "december",
    // Russian.
    "понедельник",
    "вторник",
    "среда",
    "четверг",
    "пятница",
    "суббота",
    "воскресенье",
    "январь",
    "февраль",
    "март",
    "апрель",
    "май",
    "июнь",
    "июль",
    "август",
    "сентябрь",
    "октябрь",
    "ноябрь",
    "декабрь",
    // Arabic.
    "الإثنين",
    "الاثنين",
    "الثلاثاء",
    "الأربعاء",
    "الاربعاء",
    "الخميس",
    "الجمعة",
    "السبت",
    "الأحد",
    "الاحد",
    "يناير",
    "فبراير",
    "مارس",
    "أبريل",
    "ابريل",
    "مايو",
    "يونيو",
    "يوليو",
    "أغسطس",
    "اغسطس",
    "سبتمبر",
    "أكتوبر",
    "اكتوبر",
    "نوفمبر",
    "ديسمبر",
    // Common short forms a date or "sent" line carries.
    "okt",
    "вт",
    "ср",
];

/// Role mailboxes: a local part that is entirely one of these never seeds a
/// name, and none of their tokens ever propagates.
const ROLE_LOCAL_PARTS: &[&str] = &[
    "contact",
    "info",
    "hr",
    "admin",
    "office",
    "support",
    "sales",
    "hello",
    "hi",
    "team",
    "noreply",
    "no-reply",
    "enquiries",
    "inquiries",
    "billing",
    "accounts",
    "compta",
    "facturation",
    "rh",
    "service",
    "mail",
    "postmaster",
    "webmaster",
    "bureau",
    "accueil",
    "vente",
    "commercial",
    "direction",
    "kontak",
    "inligting",
    "ondersteuning",
    "verkope",
    "rekeninge",
    "navrae",
    "kapcsolat",
    "ertekesites",
    "értékesítés",
    "szamla",
    "számla",
    "ugyfelszolgalat",
    "ügyfélszolgálat",
    "контакт",
    "инфо",
    "поддержка",
    "продажи",
    "почта",
    "اتصال",
    "معلومات",
    "دعم",
    "مبيعات",
    "بريد",
];

/// [`ROLE_LOCAL_PARTS`], folded once so a token that [`fold`] normalised matches
/// its accented or hamzated spelling.
pub(super) static ROLE_LOCAL_WORDS: std::sync::LazyLock<HashSet<String>> =
    std::sync::LazyLock::new(|| ROLE_LOCAL_PARTS.iter().map(|word| fold(word)).collect());

/// Surname particles of every corpus language (P3, over-masking).
///
/// These join a given name to its family name (`van der Berg`, `Ибн Сина`,
/// `al-Rashid`). As structural words they never propagate alone; they are
/// masked only as part of a strong seed's full sequence. `Mac`/`Mc` behave as
/// prefixes only: they join a following name, never a surname on their own.
pub(super) const STRUCTURAL_PARTICLES: &[&str] = &[
    "ибн", "бен", "ван", "фон", "ibn", "bin", "bint", "ben", "abu", "al", "el", "van", "von",
    "der", "den", "ter", "du", "des", "da", "di", "del", "della", "dos", "mac", "mc",
];

/// Function words, roles and structural labels that no rule may seed or emit,
/// in any case. [`super::cues::RULE_WORDS`] is folded into it, so greetings, closings, titles
/// and discourse words are covered too.
pub(super) static STRUCTURAL_WORDS: std::sync::LazyLock<HashSet<String>> =
    std::sync::LazyLock::new(|| {
        RULE_WORDS
            .iter()
            .map(String::as_str)
            .chain(FUNCTION_WORDS.iter().copied())
            .chain(HEADER_LABELS.iter().copied())
            .chain(CALENDAR_WORDS.iter().copied())
            .chain(COURTESY_WORDS.iter().copied())
            .chain(STRUCTURAL_PARTICLES.iter().copied())
            .flat_map(|phrase| phrase.split(|ch: char| !ch.is_alphanumeric()))
            .filter(|word| !word.is_empty())
            .map(fold)
            .collect()
    });

/// Cue words that a birth date follows, lowercased.
pub(super) const DOB_CUES: &[&str] = &[
    "né le",
    "nee le",
    "née le",
    "ddn",
    "date of birth",
    "dob",
    "born",
    "gebore",
    "geboren",
    "születési",
    "született",
    "szuletesi",
    "родился",
    "родилась",
    "дата рождения",
    "تاريخ الازدياد",
    "تاريخ الميلاد",
    "مولود",
    "مولودة",
];
