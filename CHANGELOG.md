# Changelog

All notable changes to the Auxesis privacy kernel are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Secret shapes for New Relic, Docker, GitLab runner, Mailgun and DigitalOcean
  tokens, AWS key pairs and scheme-less `user:pass@host` links; key and
  password labels in Afrikaans, Hungarian, Slovenian and Chinese.
- Labelled dates of birth in those languages, Chinese `年月日` dates,
  `né(e) en … le …` and genealogical `b. …`.
- `gate.restore()` helper, plain-text views and a scrub registry.
- crates.io metadata and per-crate READMEs; packages are named `auxesis-*`
  (library names unchanged). Nothing is published yet.

### Changed

- CI on GitHub runs the full kernel gate: fmt, clippy, tests on macOS and
  Linux, rustdoc, cargo deny and the in-repo privacy eval.
- Tests run in release, where the linear-time bars apply.

### Fixed

- An IBAN glued to text on both sides, or wrapped over two lines, is hidden.

## [0.1.0] - 2026-11-01

First public release.

### Added

- `auxesis-kernel-core`: privacy modes, the table of paths out, `admit()` and
  the `Grant` only it can mint, plus configuration, budgets, jobs and the
  filesystem gateways.
- `auxesis-kernel-privacy`: deterministic detectors for bank accounts, payment
  cards, national ID numbers, health terms, secrets, e-mail addresses, phone
  numbers, dates of birth and more; keyed tokens, restore, the fail-closed
  `Gate`, an encrypted session vault and a contacts index.
- `auxesis-kernel-broker`: ordered tool rules, approval requests, taint tracking
  for untrusted content, log redaction and audit events.
- `auxesis-kernel-net`: one HTTP client factory with an SSRF guard, DNS pinning,
  redirect re-checks, size and time caps, and an egress allow-list.
- `auxesis-kernel-mcp`: a bounded JSON-RPC 2.0 / MCP client for stdio and HTTP
  tool servers, with sandbox profiles and tool identity pinning.
- `auxesis-gliner2`: an optional local GLiNER2 entity runner over ONNX Runtime,
  loaded at run time and off by default.
- `privacy-eval`: the offline harness that scores the detectors against an
  invented, labelled corpus.
- Examples for tokenising text, using the gate and masking standard input, and
  a five-minute quickstart in the repository README.

### Notes

- Packages carry the `auxesis-` prefix; the library names stay `kernel_core`,
  `kernel_privacy`, `kernel_broker`, `kernel_net`, `kernel_mcp` and
  `gliner2_rs`, so `use kernel_privacy::…` is unchanged.
- Person and company names are not masked, by design. Postal addresses and
  dates of birth are only partly detected; the repository README reports the
  measured recall and the known gaps.
- Detection runs locally: no model, no network call and no telemetry.
