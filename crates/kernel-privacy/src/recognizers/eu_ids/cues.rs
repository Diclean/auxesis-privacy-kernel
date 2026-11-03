//! The label words of every EU rule, each a sequence of words.

use super::Cue;

/// The label words of the German Steuer-ID.
pub(super) static DE_CUES: &[Cue] = &[
    &["steuer", "id"],
    &["steueridentifikationsnummer"],
    &["idnr"],
];

/// The label words of the Spanish DNI and NIE.
pub(super) static ES_CUES: &[Cue] = &[
    &["dni"],
    &["d", "n", "i"],
    &["nie"],
    &["nif"],
    &["identidad"],
];

/// The label words of the Italian codice fiscale.
pub(super) static IT_CUES: &[Cue] = &[&["codice", "fiscale"], &["cod", "fisc"], &["cf"]];

/// The label words of the Dutch BSN.
pub(super) static NL_CUES: &[Cue] = &[
    &["bsn"],
    &["burgerservicenummer"],
    &["citizen", "service", "number"],
];

/// The label words of the Belgian national number.
pub(super) static BE_CUES: &[Cue] = &[
    &["rijksregisternummer"],
    &["national", "number"],
    &["nationale", "nummer"],
    &["bisnummer"],
];

/// The label words of the Polish PESEL.
pub(super) static PL_CUES: &[Cue] = &[&["pesel"]];

/// The label words of the Portuguese NIF, and the tax number in English.
pub(super) static PT_CUES: &[Cue] = &[
    &["nif"],
    &["contribuinte"],
    &["tax", "number"],
    &["taxpayer", "number"],
    &["tax", "identification", "number"],
];

/// The label words of the Austrian social insurance number.
pub(super) static AT_CUES: &[Cue] = &[
    &["sv", "nr"],
    &["svnr"],
    &["sozialversicherungsnummer"],
    &["versicherungsnummer"],
    &["social", "insurance", "number"],
];

/// The label words of the Irish PPSN.
pub(super) static IE_CUES: &[Cue] = &[
    &["ppsn"],
    &["pps", "number"],
    &["pps", "no"],
    &["personal", "public", "service", "number"],
];

/// The label words of the Swedish personnummer.
pub(super) static SE_CUES: &[Cue] = &[
    &["personnummer"],
    &["personnr"],
    &["samordningsnummer"],
    &["personal", "identity", "number"],
];

/// The label words of the Romanian CNP.
pub(super) static RO_CUES: &[Cue] = &[
    &["cnp"],
    &["c", "n", "p"],
    &["cod", "numeric", "personal"],
    &["personal", "numeric", "code"],
];

/// The label words of the Czech and Slovak rodné číslo.
pub(super) static CZ_CUES: &[Cue] = &[
    &["rodné", "číslo"],
    &["rodne", "cislo"],
    &["rč"],
    &["r", "č"],
    &["birth", "number"],
];

/// The label words of the Greek AFM, the tax number.
pub(super) static GR_AFM_CUES: &[Cue] = &[
    &["afm"],
    &["a", "f", "m"],
    &["tax", "identification", "number"],
    &["tax", "number"],
];

/// The label words of the Greek AMKA, the social insurance number.
pub(super) static GR_AMKA_CUES: &[Cue] = &[
    &["amka"],
    &["a", "m", "k", "a"],
    &["social", "insurance", "number"],
];

/// The label words of the Bulgarian EGN.
pub(super) static BG_CUES: &[Cue] = &[
    &["egn"],
    &["e", "g", "n"],
    &["unified", "civil", "number"],
    &["civil", "number"],
];
