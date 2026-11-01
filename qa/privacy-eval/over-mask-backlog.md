# Over-masking backlog (known names)

The known-contacts slice (`known_contacts.jsonl`) lists only spans that must
mask. It has no negative cases, so the over-masks below are kept here as a
target list for the follow-up (seal round 7, F3, reclassified P3). Each one
is a contact name written as an ordinary word and masked where it should stay
in clear. No lexicon is planned for this round.

## Common-word name parts (contact = the same word)

Each word is a contact name, masked in a sentence where it is a common word.
The example sentences are illustrative; they have not been run against the
recogniser yet.

| word | example text that must stay clear |
|------|-----------------------------------|
| mark | "mark the date" |
| jan | "jan. the report is due" |
| bill | "the bill is paid" |
| grace | "with grace and speed" |
| frank | "to be frank, no" |
| faith | "keep the faith" |
| pat | "a pat on the back" |
| sue | "I won't sue" |
| art | "the art of it" |
| dawn | "at dawn we left" |
| iris | "the iris scan" |
| ivy | "poison ivy" |
| jack | "jack of all trades" |
| max | "max speed" |
| chase | "chase the lead" |
| luz | "la luz del día" |
| paz | "paz y amor" |
| aimé | "aimé le café" |
| aurore | "à l'aurore" |
| ernst | "ernst ist das leben" |
| constant | "a constant rate" |
| victor | "victor hugo wrote it" |
| hunter | "the hunter season" |

## Other P3 strings (seal round 7)

- Mueller ↔ Muller ASCII cross-spelling (an ASCII spelling of the umlaut
  name, both directions).
- U+02B9 (modifier letter prime) as an apostrophe stand-in.
- `WILL YOU` (all caps, a common phrase with a name part).
- `low. Erik Bäck`: a sentence break before the name merges the two regions.
- `forget_value` with inner spaces, and diacritic-less surfaces for
  `forget_value` (erasure must cover both).
