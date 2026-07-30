# Changelog

All notable changes to UEWorkshopScanner will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases use [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0-alpha.1] - 2026-07-29

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
- Versioned report schema, public scanner facade, and embedded game profiles.
- Direct JSON file output for launcher and in-game integrations.
- Observe-only Meccha UE4SS prototype and Nexus/Thunderstore packaging.
- Decoder-free Windows CI artifacts and an experimental complete prerelease.

### Changed

- Split the CLI, scan orchestration, decoder boundary, and detection pipeline
  into library modules behind a thin binary entry point.
- Updated both hashing paths to `sha2` 0.11.
- Replaced process-environment Oodle configuration with a race-safe,
  process-wide adapter API.

[Unreleased]: https://github.com/ifBars/UEWorkshopScanner/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/ifBars/UEWorkshopScanner/releases/tag/v0.1.0-alpha.1
