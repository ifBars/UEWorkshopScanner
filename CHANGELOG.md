# Changelog

All notable changes to UEWorkshopScanner will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases use [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Rust CLI for in-process UE5 IoStore scanning through retoc.
- Workshop directory scanning with recursive IoStore discovery.
- Parallel ASCII and UTF-16 cooked-asset marker analysis.
- Correlated Meccha Chameleon dropper behavior rules UWS101-UWS114.
- Loose-file and disguised-executable rules UWS200-UWS202.
- Threat-family classification, final disposition, and structured completeness.
- Fail-closed `allow`, `review`, `block`, and `incomplete` verdicts.
- Safe Oodle adapter without runtime downloads.
- Bundled-decoder license display and one-time acceptance.
- Deterministic Windows release packaging with SHA-256 checksums.
- Process-level CLI contract tests.
- Integration strategy for launchers, Workshop watchers, and game-side gates.
- Structured issue form for requesting support for additional Unreal games.

### Changed

- Split the CLI, scan orchestration, decoder boundary, and detection pipeline
  into library modules behind a thin binary entry point.
- Updated both hashing paths to `sha2` 0.11.

[Unreleased]: https://github.com/ifBars/UEWorkshopScanner/commits/main
