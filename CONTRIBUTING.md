# Contributing

Thank you for helping. This is a small project with one maintainer, so short,
focused pull requests are easiest to review.

## Before you open a pull request

Run the same checks as CI:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
scripts/check-egress.sh
```

If you change a detector, also run `cargo run -p privacy-eval --release --locked`
and paste the table it prints into the pull request.

## Rules for changes

- **Add a test with every fix.** A bug fix comes with a test that fails without it.
- **Never weaken a rule.** A privacy change may hide more, not less. If a value
  was hidden before your change, it must still be hidden after it.
- **Use invented data only.** No real names, e-mails, phone numbers, IBANs, IDs
  or keys in code, tests or issues. Use `example.com`, test card numbers and
  obviously fake keys.
- **No new HTTP client** unless it is listed in `docs/egress.md`
  (`scripts/check-egress.sh` checks this).
- **No `unsafe`** in the crates that forbid it.
- **New dependencies** need a reason in the pull request and must pass
  `cargo deny check`.

## Security issues

Do not report them in a public issue or pull request. See [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the license of this repository, the Apache
License, Version 2.0 (inbound = outbound). By sending a contribution you agree
that it is licensed under the same terms as the rest of the project.
