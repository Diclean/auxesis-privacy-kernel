//! EU-KERNEL-1a: the EU national and tax identifiers the privacy kernel
//! leaks today.
//!
//! * Germany: the Steuer-ID, eleven digits, ISO 7064 MOD 11,10;
//! * Spain: the DNI (eight digits and a letter) and the NIE (`X`, `Y` or `Z`,
//!   seven digits and a letter), the letter being the mod-23 check and
//!   standing after a hyphen, a space, a dot or a single line break;
//! * Italy: the codice fiscale, sixteen characters with the odd and even
//!   check character, which is a letter, the shape keeping the place of three
//!   digits and a digit of the omocodia standing for its letter;
//! * the Netherlands: the BSN, nine digits, the eleven-proof;
//! * Belgium: the national number, eleven digits or twelve with the century
//!   in front, as a birth after 2000 is written, the check then computed on
//!   the number with that century in front;
//! * EU-KERNEL-1b: the Polish PESEL, the Portuguese NIF (after a label
//!   only), the Austrian SV-Nr, the Irish PPSN and the Swedish personnummer;
//! * EU-KERNEL-1c: the Romanian CNP, the Czech and Slovak rodné číslo (the
//!   nine digits before 1954 after a label only), the Greek AFM (after a label
//!   only) and AMKA, and the Bulgarian EGN.
//!
//! Every value is hidden in Private mode and removed in Open mode, with a
//! label and without one. A value whose check digit fails stays in clear
//! unless a label names it. Every value is invented.

mod belgium;
mod corpus;
mod germany;
mod helpers;
mod italy;
mod kernel_1b;
mod kernel_1c;
mod netherlands;
mod shapes;
mod spain;
mod sweep;
mod timing;
