# Auxesis privacy kernel

A Rust library that checks text before it leaves your machine.

You give it a string, for example a prompt for a cloud AI model. It finds the
sensitive values in it (bank accounts, card numbers, ID numbers, health terms,
API keys, e-mail addresses, phone numbers) and swaps each one for a token such as
`⟦IBAN_56E65D55C146⟧`. The model only ever sees the tokens. When the answer comes
back, the kernel puts the real values back in, on your machine. Detection runs
locally: no AI model, no network call, no telemetry.

It is the privacy layer of [Auxesis](#about), a personal assistant that runs on
one Mac, published on its own so other projects can use it.

## What it hides

There are two modes. **Private** replaces every value it finds with a token that
you can restore later. **Open** leaves ordinary values as they are and only tells
you what Private would have hidden, except for the most sensitive classes, which
it removes in both modes. One detail: the Open report also counts the names it
found, and Private never masks a name. See [Names](#names).

| Class | Examples | Private | Open |
| --- | --- | --- | --- |
| Bank accounts | IBAN | token | removed (`[iban removed]`) |
| Payment cards | Visa, Mastercard, … (Luhn-checked) | token | removed (`[card removed]`) |
| ID numbers | passport, French NIR, UK NI number, Hungarian TAJ and tax ID, South African ID, Chinese ID | token | removed (`[id removed]`) |
| Health | conditions, medicines, care terms | token | removed (`[health removed]`) |
| Secrets | API keys, tokens, passwords, private keys | token | removed (`[secret removed]`) |
| E-mail addresses | `ana@example.com` | token | kept, reported |
| Phone numbers | `+44 20 7946 0958`, national forms | token | kept, reported |
| Dates of birth | `born on 12/03/1985` | token | kept, reported |
| Other sensitive categories | religion, ethnicity, sexual orientation, union membership | token | kept, reported |
| Company IDs | French SIREN and VAT numbers | token | kept, reported |
| Network | IPv4 addresses, URLs | token | kept, reported |

A **token** is an opaque label made from a keyed hash (HMAC-SHA-256) of the
value. The same value gets the same token within one session, and a different
token with another key. Only your process holds the table that maps tokens back
to values.

## What it does not do

Be clear about these limits before you rely on it.

- **Names are not hidden.** Person and company names pass through as written,
  in both modes. This is a deliberate choice: name detection guesses wrong too
  often, and a wrong guess either leaks or breaks the text. The
  [Names](#names) section says what the name tools still do.
- **Postal addresses are only partly detected.** Measured Private recall is
  40.8 % on Gretel (n = 4,304) and 72.1 % on Nemotron (n = 920); the 100 % TAB
  cell is six street-number addresses. Treat an address as a known gap.
- **Languages in scope:** English first, then French, Afrikaans, Hungarian,
  Slovenian and Chinese. Other languages may work for structured values (an IBAN
  is an IBAN), but word lists such as health terms are only checked in these.
- **Detection is pattern-based.** It catches the common written forms of each
  class. Values that are split, spelled out, encoded in unusual ways or hidden in
  images can be missed. Measure it on your own data before you trust it.
- **It does not remove every identifying detail.** The text around a token can
  still say a lot about a person. It reduces what leaves; it does not prove that
  nothing identifying leaves, and it is not a legal compliance tool.

## Names

Names are not masked: a person name or a company name leaves the Mac as written,
in Private and in Open mode. On the Private path `egress_detector` in
`safetext/detector.rs` drops every name span on purpose, so no name is tokenised
or removed.
The name tools still have a job: the contact index finds a known contact in a
text and matches an e-mail address, a phone number or an IBAN to that person;
the known-names dictionary matches the names the owner gave it; the e-mail layer
reads the names in a header, a greeting or a sign-off; the optional GLiNER2
model finds the rest. In Open mode the names found are counted in the report.
E-mail addresses, phone numbers, ID numbers, IBANs, payment cards, health terms
and secrets are masked in both modes; only the names stay in clear.

## Measured recall

Two runs, published as measured. Neither is a guarantee about your text.

### Held-out set (internal)

The kernel keeps an internal held-out set of 250 invented values in 184 carrier
texts, in FR/EN/AF/HU/SL/ZH. It is not in this repository, and fixes must not be
tuned against it. A value counts as hidden only when no 6-character run of it is
readable in the output; a partial mask or a gate refusal is a miss.

| class | n | Private | Open |
| --- | ---: | ---: | ---: |
| IBAN | 40 | 100.00 % | 100.00 % |
| card | 35 | 100.00 % | 100.00 % |
| ID | 70 | 95.71 % | 94.29 % |
| secret | 45 | 93.33 % | 93.33 % |
| health | 60 | 81.67 % | 81.67 % |
| **all** | **250** | **93.20 %** | **92.80 %** |

The Tier C bar is 99.5 %. **It is not met yet**: Private is 93.20 % and Open is
92.80 % on this set. These are measured recall values on invented data, not a
guarantee about other text. Details: [`qa/privacy-eval/RECALL.md`](qa/privacy-eval/RECALL.md).

### Public benchmarks

EXT-BENCH-1 ran the production gate in Private mode over three public PII
corpora on 2026-11-01, Standard detection only, at most 5,000 texts per set.
Recall is per class and per set; `n` is the number of gold values in that set's
sample, and `–` means the set has no scorable label for that class.

| class | Nemotron-PII | Gretel | TAB |
| --- | ---: | ---: | ---: |
| e-mail | 100.0 % (3,218) | 99.8 % (1,300) | – |
| phone | 99.0 % (1,835) | 96.9 % (915) | – |
| IBAN | – | 96.4 % (195) | – |
| card | 99.9 % (769) | 99.2 % (118) | – |
| national ID | 100.0 % (331) | 93.5 % (153) | – |
| passport | – | 89.0 % (136) | – |
| driving licence | 76.6 % (167) | 100.0 % (140) | – |
| tax ID | 100.0 % (90) | – | – |
| secret | 85.0 % (1,672) | 61.5 % (494) | – |
| health | 97.3 % (1,564) | – | – |
| postal address | 72.1 % (920) | 40.8 % (4,304) | 100.0 % (6) |
| date of birth | 97.5 % (1,062) | 69.1 % (230) | 3.4 % (235) |

TAB's 241 scored values are only dates of birth and six street-number addresses,
so its cells say nothing about the other classes.

Known gaps: postal address is the weak class (Gretel 40.8 %, n = 4,304;
Nemotron 72.1 %, n = 920; TAB 100 % is six street-number addresses). Other weak
cells: secret on Gretel 61.5 % (n = 494), date of birth on TAB 3.4 % (n = 235)
and Gretel 69.1 % (n = 230), driving licence on Nemotron 76.6 % (n = 167), and
national ID on Gretel 93.5 % (n = 153). Cards read 99.9 % on Nemotron and 99.2 %
on Gretel; many synthetic cards are Luhn-invalid and Private catches them by
context, so that is not a checksum result. The run predates the compact and
spaced IBAN fix (#475), so IBAN should be re-measured on current code.

The three open-licence corpora:

- [nvidia/Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII) —
  CC BY 4.0, NVIDIA Corporation.
- [gretelai/synthetic_pii_finance_multilingual](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual) —
  Apache-2.0, Gretel AI.
- [TAB, the Text Anonymisation Benchmark](https://github.com/NorskRegnesentral/text-anonymisation-benchmark) —
  MIT, Norsk Regnesentral.

No dataset row or raw value is in this repository.

## Quickstart (5 minutes)

You need Rust (the version is pinned in `rust-toolchain.toml`). The crates are
not on crates.io yet, so add them from Git:

```toml
[dependencies]
auxesis-kernel-privacy = { git = "https://github.com/Diclean/auxesis-privacy-kernel", tag = "v0.1.9" }
auxesis-kernel-core = { git = "https://github.com/Diclean/auxesis-privacy-kernel", tag = "v0.1.9" }
getrandom = "0.2"
```

The packages carry the `auxesis-` prefix and keep their short library names, so
the examples below still `use kernel_privacy::…` and `use kernel_core::…`.

### 1. Tokenise a string, then restore the reply

```rust
use kernel_privacy::{Anonymizer, Registry, UnknownPolicy};

let text = "Pay FR76 3000 6000 0112 3456 7890 189 and mail ana@example.com.";

// Find the values. `without_names()` matches what Private mode hides.
let spans = Registry::new().without_names().analyze(text);

// Replace them with tokens. Use a fresh random key for each session.
let mut key = [0u8; 32];
getrandom::getrandom(&mut key).unwrap();
let mut anonymizer = Anonymizer::new(key);
let (masked, tokens) = anonymizer.anonymize(text, &spans);
// masked: "Pay ⟦IBAN_13CF…⟧ and mail ⟦EMAIL_C3C9…⟧."

// Send `masked` to the model. Restore its answer on your machine.
let reply = format!("Done: {masked}");
let restored = Anonymizer::restore(&reply, &tokens, UnknownPolicy::Redact);
assert!(restored.is_clean()); // no token the model made up
println!("{}", restored.text);
```

`UnknownPolicy::Redact` replaces any token that this session did not create (for
example one the model invented) instead of guessing.

### 2. Use the gate, so only checked text can be sent

(An excerpt; the full program is `examples/quickstart_gate.rs`.)

The gate is the safer way in a real application. You first ask the kernel for a
**grant** for one path out of your program (here `A1`, chat with a hosted model).
The gate then returns a `SafeText`. It has no public constructor, so if your
sending code only accepts `SafeText`, unchecked text cannot reach it: the
compiler refuses.

```rust
use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::Gate;

let to_model = Context { destination: Destination::Vendor("hosted-model".into()) };
let Decision::Allow(grant) = admit(PathId::A1, PrivacyMode::Private, &to_model) else {
    panic!("this path is refused");
};

let mut gate = Gate::for_grant(&grant, key);
let (safe, report) = gate.text("IBAN GB82 WEST 1234 5698 7654 32, api key sk-test-0000")?;
println!("{}", safe.as_str()); // IBAN ⟦IBAN_…⟧, api key ⟦SECRET_…⟧
println!("{report}");          // masked: IBAN=1 SECRET=1

// The token -> value pairs. Keep them on the machine; never send them.
let pairs = gate.take_minted();
```

The gate fails closed: if detection errors, or the masked text still contains a
value it can detect, you get an error and nothing to send.

Both examples are in this repository and run as they are:

```sh
cargo run -p auxesis-kernel-privacy --example quickstart_mask
cargo run -p auxesis-kernel-privacy --example quickstart_gate
```

## Everyday use

These are the three ways people use the kernel day to day. The examples below
use invented values and run offline: the model call is faked, so there is no
network and no API key.

`Registry` and `Anonymizer` are the lower-level parts; the gate adds extra
passes, so use the gate unless you know why not.

### 1. Your app calls a cloud model

**The situation:** your app sends a prompt to a hosted model and shows the
answer.

**What it hides:** the values it detects leave as tokens, including bank
accounts, cards, ID numbers, health terms, API keys, e-mail addresses and phone
numbers. **What it does not hide:** person and company names stay clear by
design; postal addresses and dates of birth are only partly caught — the
measured recall table shows the rates.

```rust
use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{Gate, PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};

let text = "Alice from ACME asks: IBAN GB82 WEST 1234 5698 7654 32, mail alice@example.com.";
let to_model = Context { destination: Destination::Vendor("hosted-model".into()) };
let Decision::Allow(grant) = admit(PathId::A1, PrivacyMode::Private, &to_model) else {
    panic!("A1 is refused");
};
let mut key = [0u8; 32];
getrandom::getrandom(&mut key).expect("random session key");
let mut gate = Gate::for_grant(&grant, key);
let (safe, _report) = gate.text(text).expect("the gate fails closed");
println!("to the model: {}", safe.as_str());

let fake_model = |prompt: &str| format!("About your invoice: {prompt}");
let answer = fake_model(safe.as_str());
// The gate gives `(token, value)` pairs; fold the public placeholders back.
let restored = gate.take_minted().iter().fold(answer, |text, (token, value)| {
    text.replace(&format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}"), value)
});
println!("back to you: {restored}");
```

The gate hands out `(token, value)` pairs, not a restore object, so the snippet
folds the public placeholders back; this is the same route the crate's tests
use. The full program is
[`crates/kernel-privacy/examples/everyday_llm_call.rs`](crates/kernel-privacy/examples/everyday_llm_call.rs);
it runs offline.

### 2. Before you paste a document into a chatbot

**The situation:** you want to ask a chatbot about a document without pasting
the raw values.

**What it hides:** the same classes as above, when it detects them. **What it
does not hide:** person and company names stay clear by design; postal
addresses and dates of birth are only partly caught — the measured recall table
shows the rates.

Until a command-line tool exists (it is planned, not there yet), this example
reads a file and prints the masked text:

```rust
use std::io::{self, Read};

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::Gate;

let mut text = String::new();
io::stdin().read_to_string(&mut text).expect("read stdin");
let to_model = Context { destination: Destination::Vendor("hosted-model".into()) };
let Decision::Allow(grant) = admit(PathId::A1, PrivacyMode::Private, &to_model) else {
    panic!("A1 is refused");
};
let mut key = [0u8; 32];
getrandom::getrandom(&mut key).expect("random session key");
let mut gate = Gate::for_grant(&grant, key);
let (safe, _report) = gate.text(&text).expect("the gate fails closed");
print!("{}", safe.as_str());
```

```sh
cargo run -p auxesis-kernel-privacy --example everyday_mask_stdin < document.txt
```

The token map is thrown away, so this output is for pasting, not for restoring
the chatbot's answer.

### 3. A team that sends customer messages to an AI tool

**The situation:** a support team sends customer messages to a hosted AI tool.
**What it hides:** the kernel sits between the app and the provider. **Open**
mode hides the most sensitive classes — bank accounts, cards, IDs, health
terms, secrets, and any address or labelled date of birth it detects — and
leaves the rest readable with a report. **Private** mode tokenises every value
it detects apart from names, so more of the text becomes tokens you can restore
on the machine. **What it does not hide:** names and company names stay clear
in both modes by design, and postal addresses and dates of birth are only
partly caught — the measured recall table shows the rates. No new code for this
one: it is the same policy path as the quickstart examples.

One honest limit: it is not a legal compliance guarantee. It reduces what
leaves the machine; the measured recall table shows how much it catches.

## What is in this repository

| Package | What it does |
| --- | --- |
| `auxesis-kernel-privacy` | The detectors, tokens, the gate (`SafeText`) and an encrypted token vault. Start here. |
| `auxesis-kernel-core` | The policy: privacy modes, the list of paths out (`PathId`), `admit()` and `Grant`. Also the app plumbing: config, budgets, jobs, the STOP marker. |
| `auxesis-kernel-broker` | Rules for tool calls, taint tracking for untrusted content, log scrubbing, audit events. |
| `auxesis-kernel-net` | The one HTTP client factory, with an SSRF guard and DNS pinning. |
| `auxesis-kernel-mcp` | A client for MCP tool servers (stdio and HTTP), with sandbox profiles. |
| `auxesis-gliner2` | Optional. Runs a local GLiNER2 entity model through ONNX Runtime. Off by default and not used by the default build; see its README. |
| `qa/privacy-eval` | Scores the detectors against a labelled, invented corpus. |

The package names carry the `auxesis-` prefix; the libraries keep their short
names, `kernel_privacy`, `kernel_core`, `kernel_broker`, `kernel_net`,
`kernel_mcp` and `gliner2_rs`.

`auxesis-kernel-broker`, `auxesis-kernel-net` and `auxesis-kernel-mcp` serve the
Auxesis daemon and are tied to macOS more closely. Most users only need
`auxesis-kernel-privacy` and `auxesis-kernel-core`.

The prompt-injection corpus that the tests read and the private held-out sets
are not part of this repository.

## How the crates fit together

- **`auxesis-kernel-core`** — the policy first: privacy modes, the paths out (`PathId`), `admit()` and the `Grant` it returns. It also holds shared app plumbing (home layout, config, budgets, jobs, the STOP marker); none of it is the gate, and `admit()` never reads STOP.
- **`auxesis-kernel-privacy`** — the detectors: `Registry` finds the sensitive spans, `Anonymizer` swaps them for `⟦KIND_…⟧` tokens, and `Gate` produces the `SafeText` that only checked text can travel in.
- **`auxesis-kernel-broker`** — the tool side: `ToolRegistry`, the `Broker` that decides `allow`/`ask`/`deny` per call, taint tracking for untrusted content, the sandbox profiles and the log scrubber.
- **`auxesis-kernel-net`** — the egress side: the one HTTP client factory with the SSRF guard and DNS pinning, the web policy (allow list, budgets, ask rules) and the loopback CONNECT proxy for sandboxed extensions.
- **`auxesis-kernel-mcp`** — the MCP client: stdio and HTTP transports for JSON-RPC tool servers, the install approval, discovery, and the sandbox profile an extension runs under.
- **`auxesis-gliner2`** — optional: a local GLiNER2 entity model over ONNX Runtime, off by default and not used by the default build.

## Run the tests and the eval

```sh
cargo test --workspace --locked          # all tests
cargo test -p auxesis-kernel-privacy --locked  # just the detectors
cargo clippy --workspace --all-targets --locked -- -D warnings
scripts/check-egress.sh                  # every HTTP client is listed in docs/egress.md
cargo run -p privacy-eval --release --locked
```

`privacy-eval` prints one table: recall per tier on a held-out split, false
positives on trap cases, over-masking on normal prose, and latency. A bar it
misses is printed as `MISSED`, never rounded up. The corpus in
`qa/privacy-eval/cases/` is invented; it contains no real person's data.

## Report a security issue

Please do not open a public issue. See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## About

Auxesis is a personal assistant that runs on one Mac. A cloud model does the
reasoning, and this kernel decides what may leave the machine. The rest of
Auxesis (daemon, app, connectors) is not part of this repository.

The project is early. There is no stable API yet, and only `main` gets fixes.

## License

**Apache-2.0.** Free to use, including commercially. The full text is in
[LICENSE](LICENSE) and the notices in [NOTICE](NOTICE).
