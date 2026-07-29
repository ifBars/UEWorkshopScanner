# Contributing

Contributions are welcome, especially parser hardening, inert regression
fixtures, false-positive reductions, and documented behavior rules.

## Before opening a pull request

Run the same checks as CI:

```powershell
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
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
