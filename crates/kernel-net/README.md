# auxesis-kernel-net

The one HTTP client factory for the Auxesis privacy kernel. Every outbound
request goes through a client built here, with an SSRF guard, DNS pinning,
redirect re-checks, and size and time caps.

The policy layer also holds the egress allow-list: which origins may be
fetched, what may be sent, and how much. Callers for which visibility is a
security property use the browser path, where the rendered text is the oracle.

## Install

```toml
[dependencies]
auxesis-kernel-net = "0.1.5"
```

The package is `auxesis-kernel-net`; the library name stays `kernel_net`.

```rust
use kernel_net::{domain_matches, is_public_address, refuses_host_shape};

assert!(domain_matches("*.example.com", "api.example.com"));
assert!(!refuses_host_shape("api.example.com"));
assert!(is_public_address("1.1.1.1".parse().expect("IP address")));
```

## Licence

PolyForm-Noncommercial-1.0.0. See the repository `LICENSE`, `NOTICE` and
`COMMERCIAL.md`.
