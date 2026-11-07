# auxesis-kernel-privacy

Finds sensitive values in text and swaps each one for a restorable token, so a
cloud model sees `⟦IBAN_…⟧` instead of the account number. Detection is local
and deterministic: no model, no network call, no telemetry.

It covers bank accounts, cards, national ID numbers, health terms, secrets,
e-mail addresses, phone numbers, dates of birth and more. Names stay clear by
design; the repository README reports the measured limits.

## Install

```toml
[dependencies]
auxesis-kernel-privacy = "0.1.11"
getrandom = "0.2"
```

The package is `auxesis-kernel-privacy`; the library name stays `kernel_privacy`.

```rust
use kernel_privacy::{Anonymizer, Registry, UnknownPolicy};

let text = "Pay GB82 WEST 1234 5698 7654 32, mail alice@example.com.";
let spans = Registry::new().without_names().analyze(text);

let mut key = [0u8; 32];
getrandom::getrandom(&mut key).expect("random session key");
let (masked, tokens) = Anonymizer::new(key).anonymize(text, &spans);
println!("{masked}");

let reply = Anonymizer::restore(&format!("Done: {masked}"), &tokens, UnknownPolicy::Redact);
assert!(reply.is_clean());
println!("{}", reply.text);
```

## Licence

Apache-2.0. Free to use, including commercially. See the repository `LICENSE`
and `NOTICE`.
