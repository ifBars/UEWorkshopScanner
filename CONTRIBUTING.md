# Contributing

Contributions are welcome, especially parser hardening, inert regression
fixtures, false-positive reductions, and documented behavior rules.

## Before opening a pull request

Run the same checks as CI:

```powershell
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo +1.88.0 check --locked --all-targets
```

Keep changes focused and explain how scan completeness, verdicts, and false
positives are affected.

## Detection rules

New blocking rules should:

1. represent a behavior chain rather than a single dual-use marker;
2. cite a public technical source or a privately documented sample;
3. include an inert positive test;
4. include a benign negative test;
5. preserve deterministic results;
6. return `incomplete` instead of `allow` when required evidence cannot be
   inspected.

Keep the detection layers separate: byte markers belong in `markers.rs`,
correlated low-level findings in `rules.rs`, named behavior variants in
`threat_intel.rs`, and input/parser coverage failures in the completeness
model. Do not teach a primitive rule to make the final product verdict.

Keep process and product concerns separate too:

- `main.rs` only starts the CLI;
- `cli.rs` owns arguments, terminal output, and exit codes;
- `scanner.rs` coordinates the scan and builds the report;
- `oodle.rs` owns decoder verification and binary-license handling.

Put focused unit tests beside the module they cover. Put process-level CLI
contracts in `tests/`.

## Samples and licensed files

Never commit:

- malware or weaponized proof-of-concept files;
- private Workshop maps;
- `.pak`, `.utoc`, `.ucas`, `.uasset`, or extracted Unreal content;
- Oodle or other proprietary native libraries;
- game binaries, decryption keys, or mappings.

Use inert marker strings in unit tests. If a real sample is required for
research, keep it outside the repository and document only non-sensitive,
reviewable findings.

## Dependency changes

The scanner processes attacker-controlled data. Parser, decompressor, and
native-loading changes are security-sensitive. Pin Git dependencies to exact
revisions, commit `Cargo.lock`, and explain any new network or native-code
surface.
