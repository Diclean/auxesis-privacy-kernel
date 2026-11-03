# Changelog

All notable changes to the Auxesis privacy kernel are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-03

First release. Not yet published to crates.io.

### Added

- `kernel-core`: privacy modes, the table of paths out, `admit()` and the
  `Grant` only it can mint, plus configuration, budgets, jobs and the
  filesystem gateways.
- `kernel-privacy`: deterministic detectors for bank accounts, payment cards,
  national ID numbers, health terms, secrets, e-mail addresses, phone numbers,
  dates of birth and more; keyed tokens, restore, the fail-closed `Gate`, an
  encrypted session vault and a contacts index.
- `kernel-broker`: ordered tool rules, approval requests, taint tracking for
  untrusted content, log redaction and audit events.
- `kernel-net`: one HTTP client factory with an SSRF guard, DNS pinning,
  redirect re-checks, size and time caps, and an egress allow-list.
- `kernel-mcp`: a bounded JSON-RPC 2.0 / MCP client for stdio and HTTP tool
  servers, with sandbox profiles and tool identity pinning.
- `gliner2-rs`: an optional local GLiNER2 entity runner over ONNX Runtime,
  loaded at run time and off by default.
- `privacy-eval`: the offline harness that scores the detectors against an
  invented, labelled corpus.
- Examples for tokenising text, using the gate and masking standard input, and
  a five-minute quickstart in the repository README.

### Notes

- Person and company names are not masked, by design. Postal addresses and
  dates of birth are only partly detected; the repository README reports the
  measured recall and the known gaps.
- Detection runs locally: no model, no network call and no telemetry.
