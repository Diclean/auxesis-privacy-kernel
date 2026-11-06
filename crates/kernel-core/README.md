# auxesis-kernel-core

The policy half of the Auxesis privacy kernel. It answers one question before
text leaves the machine: may this path send it, and in which privacy mode?

It holds the privacy modes, the list of paths out (`PathId`), `admit()` and the
`Grant` it returns, plus shared configuration, budget, job and filesystem
helpers. `Grant` has no public constructor, so code that only accepts a `Grant`
cannot run without a policy decision.

## Install

```toml
[dependencies]
auxesis-kernel-core = "0.1.10"
```

The package is `auxesis-kernel-core`; the library name stays `kernel_core`.

```rust
use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};

let to_model = Context { destination: Destination::Vendor("hosted-model".into()) };
let Decision::Allow(grant) = admit(PathId::A1, PrivacyMode::Private, &to_model) else {
    panic!("path A1 is refused");
};
println!("{:?} may send in {:?} mode", grant.path(), grant.mode());
```

## Licence

Apache-2.0. Free to use, including commercially. See the repository `LICENSE`
and `NOTICE`.
