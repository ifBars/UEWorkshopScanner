# Changelog

All notable changes to UEWorkshopScanner will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases use [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0-alpha.4] - 2026-07-30

### Fixed

- Raised the shared decoded-item limit from 32 MiB to 512 MiB so legitimate
  large Unreal map and texture assets can be inspected completely.
- Replaced repeated whole-buffer text conversions with a single byte-oriented
  multi-pattern pass, substantially reducing large-asset scan time and memory.
- Decode large IoStore chunks sequentially while retaining parallel scanning
  for ordinary chunks.
- Include the actual chunk size and configured limit in incomplete-scan
  diagnostics.
- Attach bounded evidence records to findings with the exact matched value,
  marker category, byte offset, and text encoding.
- Show finding evidence directly in both summary output and the desktop app.
- Keep one stable desktop window size and switch between map selection and
  results, with a dedicated **Scan another map** action.

## [0.1.0-alpha.3] - 2026-07-30

### Added

- Player-facing Dioxus desktop app with folder selection, drag and drop, and
  plain-language scan results.
- In-app first-run review and acceptance of the bundled Oodle terms.
- Complete desktop and CLI archives with checksums and dependency licenses.

### Changed

- Reused the scanner as a Rust library from both the GUI and CLI instead of
  requiring the desktop app to launch a separate executable.

## [0.1.0-alpha.2] - 2026-07-30

### Added

- Human-readable `--format summary` and `--summary` CLI output with the final
  blocking recommendation, verdict, completeness, triggered rules, and
  analysis issues.
- Experimental Meccha Chameleon UE4SS integration with automatic pre-load
  scanning and player notification.
- Generated Rust dependency license inventory.

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

[Unreleased]: https://github.com/ifBars/UEWorkshopScanner/compare/v0.1.0-alpha.4...HEAD
[0.1.0-alpha.4]: https://github.com/ifBars/UEWorkshopScanner/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/ifBars/UEWorkshopScanner/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/ifBars/UEWorkshopScanner/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/ifBars/UEWorkshopScanner/releases/tag/v0.1.0-alpha.1
