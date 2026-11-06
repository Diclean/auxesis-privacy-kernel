# auxesis-kernel-broker

Decides whether a tool call may run, and keeps a record of the decision. Rules
are ordered `allow` / `ask` / `deny` per agent; every decision can be audited,
and untrusted content is tracked so it cannot quietly become an instruction.

It also holds the redaction helpers used on logs and previews, so a secret in a
tool argument does not end up in a line pasted into a ticket.

## Install

```toml
[dependencies]
auxesis-kernel-broker = "0.1.9"
```

The package is `auxesis-kernel-broker`; the library name stays `kernel_broker`.

```rust
use kernel_broker::{is_secret_shaped, redact_secrets};

let line = "request failed for sk-auxesisCanary0123456789abcdef";
assert!(is_secret_shaped("sk-auxesisCanary0123456789abcdef"));
println!("{}", redact_secrets(line));
```

The broker serves the Auxesis daemon; the scrub and redaction helpers are
useful on their own.

## Licence

PolyForm-Noncommercial-1.0.0. See the repository `LICENSE`, `NOTICE` and
`COMMERCIAL.md`.
