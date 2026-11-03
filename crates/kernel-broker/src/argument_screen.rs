//! Deterministic screen over the arguments a tool sends off the machine.
//!
//! An MCP call hands its arguments to a third-party server. Before such a call
//! runs, the engine asks [`identifier_in_arguments`]: a high-confidence
//! identifier in the arguments forces an approval whatever the allow rule says.
//! The screen runs the `kernel-privacy` registry (its public API, thresholds
//! included) over these views of the arguments:
//!
//! * the reconstructed view: every string and number value in document order,
//!   joined by `VIEW_SEPARATOR`, so an identifier split over several fields is
//!   whole without two neighbouring values reading as one grouped number;
//! * the in-order view: every key and value in document order, joined the same
//!   way;
//! * the digits-and-letters view: each leaf that is mostly digits or shaped like
//!   an IBAN, reduced to its letters and digits and joined with no separator, so
//!   an IBAN or phone split across fields with unrelated text between them is
//!   whole again;
//! * every string, object key and number leaf, one leaf at a time. The
//!   serialized JSON is not scanned: a newline inside a JSON string serializes
//!   as the two characters `\n`, which would hide a wrapped value;
//! * the decoded views of each string leaf: percent-decoding, JSON `\uXXXX`
//!   escapes, and whole-leaf hex or base64 (standard or URL-safe). Each
//!   decoder runs up to two rounds deep, and a decoded view is kept only when
//!   it is valid UTF-8 (percent and JSON escapes are kept lossily, so the ASCII
//!   around a stray byte still scans).
//!
//! A leaf whose decoding stops while it still looks encoded forces the ask too: a
//! hex run, a base64 run that decodes to text, a percent-escape share above 20 %,
//! or a `\u` escape left over. A base64 run that decodes to bytes that are not
//! text is an opaque identifier, not hidden data, and does not force it. Neither
//! does a UUID, a git SHA, a SHA-256 or SHA-512 hex digest, a ULID, a Calendar
//! event ID or a Drive file ID. The
//! screen does not decode past its depth, so a third layer is caught by that rule
//! rather than read: at the depth cap, a leaf that any decoder would still change
//! asks, whatever its share of escapes (a lone `%40` left in an address).
//!
//! The views are bounded. A base64 or hex leaf whose decoded size would exceed
//! `MAX_DECODED_PER_LEAF`, a call whose decoded views exceed
//! `MAX_DECODED_PER_CALL` in all, or a call whose leaves hold more than
//! `MAX_SCREENED_TEXT` bytes cannot be screened in full. Such a call forces the
//! ask as well: fail toward masking, never a truncated scan that passes.
//! Malformed encodings are ignored, never an error.
//!
//! A bare number, or an all-digit string, of 10 to 15 digits that opens with a
//! country code or a national trunk `0` is a phone candidate. The phone
//! recogniser rejects such a run without separators, so the screen asks. An epoch
//! timestamp (ten digits, or thirteen in milliseconds, opening with `1`) is not a
//! phone candidate: no national US number opens with `1`. A phone span made only
//! of epoch timestamps is not a hit either.
//!
//! Only the kind of identifier is returned, never the value, and no decoded
//! value is ever logged.

/// What the joined views put between two values. A phone run cannot cross it, so
/// a value ending in digits (a UUID) does not read as one grouped number with the
/// digits that open the next value (a ULID).
const VIEW_SEPARATOR: &str = " ; ";

/// The shortest leaf that may be a whole-leaf hex or base64 encoding.
const MIN_ENCODED_LEN: usize = 16;

/// The shortest base64 run, without padding, that still looks encoded.
const MIN_BASE64_RUN: usize = 24;

/// The shortest hex run that still looks encoded.
const MIN_HEX_RUN: usize = 32;

/// The least Shannon entropy, in bits per character, a base64 run needs to look
/// encoded.
const MIN_BASE64_ENTROPY: f64 = 4.0;

/// The fewest character classes (upper case, lower case, digits, `+/=-_`) a
/// base64 run needs to look encoded.
const MIN_BASE64_CLASSES: usize = 3;

/// The longest word of a snake_case or kebab-case key or label.
const MAX_DICTIONARY_WORD: usize = 12;

/// The largest share of percent escapes, in per cent, a text may carry once its
/// decoding has stopped.
const MAX_ESCAPE_PERCENT: usize = 20;

/// The largest decoded size of one encoded leaf the screen will read.
const MAX_DECODED_PER_LEAF: usize = 64 * 1024;

/// The largest total of decoded views one call may produce.
const MAX_DECODED_PER_CALL: usize = 1024 * 1024;

/// The largest total text, in bytes, of one call's leaves the screen will read.
const MAX_SCREENED_TEXT: usize = 256 * 1024;

/// How many decoding rounds stack: percent of percent, base64 of hex, and so on.
const MAX_DECODE_ROUNDS: usize = 2;

/// The plain-language label of a leaf the screen could not decode in full.
const UNSCREENED_LABEL: &str = "an encoded block too large to check";

/// The plain-language label of a leaf that still looks encoded once decoding
/// stopped.
const RESIDUE_LABEL: &str = "encoded content could not be fully checked";

/// The country calling codes of E.164, one, two or three digits each.
const COUNTRY_CODES: &str = "1 7 20 27 30 31 32 33 34 36 39 40 41 43 44 45 46 47 48 49 \
    51 52 53 54 55 56 57 58 60 61 62 63 64 65 66 81 82 84 86 90 91 92 93 94 95 98 \
    211 212 213 216 218 220 221 222 223 224 225 226 227 228 229 230 231 232 233 234 \
    235 236 237 238 239 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 \
    255 256 257 258 260 261 262 263 264 265 266 267 268 269 290 291 297 298 299 \
    350 351 352 353 354 355 356 357 358 359 370 371 372 373 374 375 376 377 378 \
    380 381 382 383 385 386 387 389 420 421 423 500 501 502 503 504 505 506 507 \
    508 509 590 591 592 593 594 595 596 597 598 599 670 672 673 674 675 676 677 \
    678 679 680 681 682 683 685 686 687 688 689 690 691 692 800 808 850 852 853 \
    855 856 880 881 882 883 886 888 960 961 962 963 964 965 966 967 968 970 971 \
    972 973 974 975 976 977 979 992 993 994 995 996 998";

/// A decoded view the screen could not produce within its caps.
struct Unscreened;

mod decode;
mod encoded;
mod false_hits;
mod phone;
mod screen;
mod shapes;
mod views;

pub use self::screen::identifier_in_arguments;

#[cfg(test)]
mod tests;
