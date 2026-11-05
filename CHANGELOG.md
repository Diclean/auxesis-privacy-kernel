# Changelog

All notable changes to the Auxesis privacy kernel are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-11-05

The changes since v0.1.3, in plain words.

### Added

- More secret forms are hidden: more issuer key prefixes (among them LangSmith,
  Pinecone, Figma, Postman, Terraform Cloud, Doppler, Databricks, SonarQube,
  CircleCI, Square, Plaid, Alibaba, Tencent, Azure AD, RubyGems and NuGet),
  Mailchimp `-usNN` keys, Slack `xoxe-` tokens, Azure `AccountKey`, Wi-Fi
  pre-shared keys and Wi-Fi QR codes, seed phrases and password hashes.
- Passwords and tokens on command lines: `curl -u`, `docker login -p`,
  `sshpass`, `redis-cli -a`, `htpasswd` with `-b`, `-B` or `-n`, and a spaced
  `mysql -p`.
- Presigned URL signatures (`sig=` and the V2 `Signature=`), Discord webhook
  URLs with or without an API version, and Digest `response=` values.
- Quoted and line-wrapped `Authorization` credentials (`Bearer`, `Basic`,
  `Token`, `SSWS` and others), and private-key bodies wrapped at 70 or 76
  columns, with or without a header.
- Key names and phrases in French, Afrikaans, Hungarian, Slovene and Chinese
  (`identifiants`, `code confidentiel`, `toegangskode`, `jelszava`, `varnostna
  koda`, `验证码`, `私钥`, `助记词`), and one-word environment names such as
  `PGPASSWORD` and `dbpassword`.

### Changed

- Health detection reaches further in FR, EN, AF, HU, SL and ZH: multi-word
  conditions, `type 2` and `stage 4` classifiers, medicines with their dose
  (`500 mg of metformin`), lab results (`HbA1c was 58 mmol/mol`, `blood
  pressure of 160/100`), pregnancy weeks, procedures, disability and allergens
  (`allergic to penicillin`). Detections are only added.
- Two harmless look-alike lines are left as written: an `Authorization` line
  whose credential is a status word such as `refreshes`, and a docs
  placeholder after `?sig=` such as `your-signature-here`. A `curl -u` value
  is still hidden whole, link or not.
- The privacy eval splits the Tier C results of each class into masked, leaked
  and blocked, in Private and Open mode. The recall figures it prints are
  unchanged.

### Removed

- `auxesis-kernel-net` drops the unused `markup5ever_rcdom` HTML tree
  dependency and the crates only it pulled in. No code changed.

## [0.1.3] - 2026-11-04

The v0.1.1 and v0.1.2 tags were made without their own section in this
file; their changes are listed here, together with the ones since v0.1.2.

### Added

- Secret shapes for New Relic, Docker, GitLab runner, Mailgun and DigitalOcean
  tokens, AWS key pairs and scheme-less `user:pass@host` links; key and
  password labels in Afrikaans, Hungarian, Slovenian and Chinese.
- Labelled dates of birth in those languages, Chinese `年月日` dates,
  `né(e) en … le …` and genealogical `b. …`.
- `gate.restore()` helper, plain-text views and a scrub registry.
- crates.io metadata and per-crate READMEs; packages are named `auxesis-*`
  (library names unchanged). Nothing is published yet.
- When untrusted content (a web page, a mail) has been read and a web request
  follows, the approval request carries the untrusted and private-data facts
  as fields, so the app can ask and label it without guessing.

### Changed

- Licence: PolyForm Noncommercial 1.0.0 instead of Apache-2.0. Noncommercial
  use stays free; commercial use needs a paid licence (see `COMMERCIAL.md`).
- The crates are versioned 0.1.3, like the tag. The v0.1.1 and v0.1.2 tags
  still said 0.1.0, so `kernel_core::VERSION`, the MCP client version and the
  HTTP user agent now say 0.1.3 instead of 0.1.0.
- `sha2` and `aes-gcm` 0.11; hashes and encrypted vault records keep the same
  bytes.
- CI on GitHub runs the full kernel gate: fmt, clippy, tests on macOS and
  Linux, rustdoc, cargo deny and the in-repo privacy eval.
- Debug builds optimise the dependencies and the detector, so tests and their
  linear-time bars run at a realistic speed.

### Removed

- Public functions and types that nothing called, here or in the Auxesis app:
  the MCP toolkit map and discovery cache, `McpResult`, `read_sse_line`,
  `sandbox_write_path`, `AddressPolicy::allow_loopback`,
  `NerConfig::with_labels`, `threshold::default_floors`, a few read-only
  getters, one builder setter, and the name-lexicon version and counts. No
  detector, gate or egress decision changed.
- `auxesis-kernel-net` drops an unused headless-browser stub and the
  dependencies only it pulled in.

### Fixed

- An IBAN glued to text on both sides, or wrapped over two lines, is hidden.
- An IBAN, card or phone number written with the digits of newer Unicode
  scripts (Garay, Kawi, Gurung Khema, Myanmar Extended-C and others) is
  detected. The kernel keeps one table of Unicode digits, so it only finds
  more than before.
- The default model prices match the providers' pricing pages, at their
  highest standard rate; none went down. Some were below the real price,
  `deepseek-flash` among them, so the daily money cap could stop spending too
  late. A `[prices]` section in the config still replaces the defaults.
- With a full Xcode selected, `git` and the other `xcrun` helpers work in the
  shell sandbox. Only shell tools get this read-and-run access, and only after
  an authenticity and ownership check on that Xcode.

### Security

- MCP: one approval installs a server; for a stdio server it is bound to the
  SHA-256 of its program and to the agent's tool allow-list. An unapproved
  server stops at the approval gate at startup, a stdio launch checks the
  program it is about to run, and a confirmation is tied to the server's
  identity; an older confirmation without it asks for approval again.
- The network guard refuses a host written as one bare number (a dotless IPv4
  address) and the ORCHID IPv6 ranges.

## [0.1.2] - 2026-11-04

Tagged without its own section; its changes are listed under 0.1.3.

## [0.1.1] - 2026-11-03

Tagged without its own section; its changes are listed under 0.1.3.

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
