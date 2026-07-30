# UEWorkshopScanner

[![CI](https://github.com/ifBars/UEWorkshopScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/ifBars/UEWorkshopScanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)

UEWorkshopScanner is a static malware scanner for Unreal Engine Workshop
content. It reads UE5 IoStore packages in-process, inspects loose files, and
returns a JSON verdict that launchers, mod managers, and game integrations can
act on.

I started this after malicious
[MECCHA CHAMELEON](https://store.steampowered.com/app/4704690/MECCHA_CHAMELEON/)
maps used Blueprint logic to write and launch a malware downloader. Meccha is
the first supported target, not the limit of the project. The scanner is
designed to add other Unreal games and threat families as we learn their
Workshop layouts and obtain safe, representative fixtures.

[Meccha Chameleon 3.1.0](https://steamcommunity.com/ogg/4704690/announcements/detail/680756685198854754)
added a security patch for MOD maps. This scanner is additional defense for
Meccha and a foundation for protecting other Unreal Workshop ecosystems.

> [!IMPORTANT]
> This is pre-release software. There is no public binary download yet, and an
> `allow` verdict is not proof that a Workshop item is safe. The current CLI
> also does not intercept a game or Steam download automatically.

## Quick start

You need Rust 1.88 or newer. Oodle-compressed content also needs an authorized
Oodle Data 2.9.10 Windows decoder.

```powershell
git clone https://github.com/ifBars/UEWorkshopScanner.git
cd UEWorkshopScanner
cargo build --locked --release
```

Scan the entire Workshop item directory when possible:

```powershell
.\target\release\ue-workshop-scanner.exe "D:\path\to\WorkshopItem" `
  --oodle-path "D:\path\to\oo2core_9_win64.dll" `
  --oodle-sha256 "<sha256>"
```

You can also scan one IoStore entry point:

```powershell
.\target\release\ue-workshop-scanner.exe "D:\path\to\Map-Windows.utoc" `
  --oodle-path "D:\path\to\oo2core_9_win64.dll" `
  --oodle-sha256 "<sha256>"
```

The scanner writes its report to standard output. Redirect it to keep a copy:

```powershell
.\target\release\ue-workshop-scanner.exe "D:\path\to\WorkshopItem" `
  --oodle-path "D:\path\to\oo2core_9_win64.dll" `
  --oodle-sha256 "<sha256>" > scan-result.json
```

Integrations can select a supported game profile and write JSON directly:

```powershell
.\target\release\ue-workshop-scanner.exe "D:\path\to\WorkshopItem" `
  --game meccha-chameleon `
  --output ".\scan-result.json"
```

Run `ue-workshop-scanner --list-games` to see the profiles embedded in the
current build.

<details>
<summary><strong>Bundled decoder builds and license acceptance</strong></summary>

Planned Windows release archives keep the scanner and an approved Oodle
decoder together. The first run will ask you to review and accept the binary
terms:

```powershell
.\ue-workshop-scanner.exe --licenses
.\ue-workshop-scanner.exe --accept-eula
```

The CLI stores acceptance in your local configuration directory. Interactive
runs prompt when you have not accepted the terms yet.

The source build never downloads a decoder. When you provide one manually, the
CLI requires its SHA-256 digest and refuses a mismatch.

</details>

## Read the result

| Verdict | Exit code | Meaning |
| --- | ---: | --- |
| `allow` | 0 | The scan completed and no current rule matched |
| `review` | 2 | Dual-use or suspicious behavior needs review |
| `block` | 3 | A high-confidence malicious behavior chain matched |
| `incomplete` | 4 | The scanner could not inspect everything safely |

The report keeps completeness separate from threat classification. A missing
container, skipped file, parser failure, or oversized item can never become
`allow`.

```json
{
  "verdict": "block",
  "complete": true,
  "disposition": {
    "classification": "KnownThreat",
    "primary_threat_family_id": "meccha-workshop-dropper"
  },
  "threat_families": [
    {
      "family_id": "meccha-workshop-dropper",
      "variant_id": "blueprint-user-write-shell-download",
      "confidence": 0.99
    }
  ]
}
```

## What it checks

UEWorkshopScanner currently looks for:

- automatic Blueprint execution tied to file writes or URL launches;
- writes into user-controlled directories, especially script files;
- PowerShell and command-shell download-and-execute chains;
- encoded commands, policy bypasses, script hosts, and common Windows LoLBins;
- raw-IP payload URLs and hidden execution;
- JSON/batch polyglot construction;
- loose scripts, executables, and files with disguised `MZ` headers;
- the documented Meccha Chameleon Workshop dropper family.

Rules correlate behavior inside the same artifact. A normal `BeginPlay`,
`ToFile`, or `powershell` string does not block a map by itself.

## Safety model

The scanner does not start Unreal Engine, run `UnrealPak.exe`, extract cooked
assets, execute scripts, or load executables found in a Workshop item.

It also has no network client. The patched Oodle adapter cannot download native
code and accepts only an explicit decoder path with a matching digest.

The container parser and native decoder still process attacker-controlled
bytes. A future desktop app should run this CLI as a disposable,
resource-limited process without administrator access or network access.

Read the [threat model](docs/threat-model.md) and
[architecture](docs/architecture.md) for the full boundary.

## Current coverage

- The scanner supports UE5 IoStore directories and direct `.utoc`/`.ucas`
  inputs.
- The scanner inspects loose Workshop files without executing them.
- The scanner inventories legacy `.pak` files but does not parse them yet.
- Encrypted containers need an authorized key and are not supported.
- Detection uses serialized markers and correlation, not full Kismet
  control-flow reconstruction.
- Native plugins, UE4SS mods, and DLL injection chains are outside the current
  scope.

### Game support

Meccha Chameleon is the initial target. Its Workshop items use Steam App ID
`4704690`, and the current threat-family rules cover the documented Meccha
Blueprint dropper chain.

Support for another Unreal game needs more than adding its name. We need to
confirm its Unreal version, Workshop directory and container layout,
compression requirements, safe test fixtures, and the point where the game
mounts downloaded content.

[Open a game-support request](https://github.com/ifBars/UEWorkshopScanner/issues/new?template=game-support.yml)
if you can provide that information. Do not upload proprietary game files,
private Workshop items, or malware to the issue.

## Integration status

UEWorkshopScanner is a manual and automation-friendly CLI with a versioned JSON
report and a reusable Rust API. A launcher can scan installed Workshop items
before starting a game, and a companion app can watch for new or updated items.

That is useful coverage, but it is not a guaranteed block for Meccha's
in-lobby flow. When a player accepts a missing map, Steam downloads it and the
game may load it immediately. A filesystem watcher can lose that race. Reliable
blocking requires a game-side integration that pauses between Steam reporting
the item as downloaded and Unreal mounting or loading it.

An observe-only Meccha UE4SS prototype can start scans from inside the game and
collect hook candidates for the download-to-load boundary. It does not block
maps yet. See the [integration prototype](integrations/meccha-ue4ss/README.md)
and the broader [integration strategy](docs/integration.md).

## Build and contribute

Run the same checks used by CI:

```powershell
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo +1.88.0 check --locked --all-targets
```

The package uses Cargo's standard library-plus-binary layout. `src/main.rs` is
only the process entry point; the scanner lives in testable library modules.

<details>
<summary><strong>Source layout</strong></summary>

```text
src/
  main.rs          process entry point
  lib.rs           crate root
  cli.rs           arguments, help, JSON output, and exit codes
  scanner.rs       scan orchestration
  game_profile.rs  embedded game support metadata
  envelope.rs      Workshop directory and loose-file inspection
  container.rs     bounded IoStore reads through retoc
  markers.rs       ASCII and UTF-16 marker extraction
  rules.rs         foundational behavior findings
  threat_intel.rs  threat-family and disposition classification
  model.rs         report and evidence types
  oodle.rs         decoder verification and binary license flow
  hashing.rs       streaming SHA-256 helpers
tests/
  cli.rs           process-level CLI contract tests
game-profiles/
  meccha-chameleon.json
integrations/
  meccha-ue4ss/     Nexus and Thunderstore UE4SS prototype
vendor/
  oodle_loader_safe/
```

</details>

New blocking rules need an inert positive test, a benign negative test, and a
documented behavior chain. Do not commit malware, private Workshop maps,
proprietary Unreal assets, Oodle binaries, or decryption keys.

See [CONTRIBUTING.md](CONTRIBUTING.md) before changing rules, parser behavior,
or completeness handling.

<details>
<summary><strong>Release packaging</strong></summary>

Maintainers can build a Windows archive from an approved local Epic
redistributable:

```powershell
.\scripts\package-windows-release.ps1 `
  -OodlePath "D:\path\to\Epic\win\redist\oo2core_9_win64.dll" `
  -Version "0.1.0"
```

The packager performs no downloads. It verifies the decoder, builds with
`Cargo.lock`, includes the required terms and notices, and writes SHA-256
checksums.

Read the [Oodle distribution assessment](docs/oodle-distribution.md) before
publishing a binary.

</details>

## Research and related work

- [2-Click Remote Code Execution in Meccha Chameleon](https://khaelkugler.com/blogs/meccha_chameleon.html)
- [Workshop map for MECCHA CHAMELEON is a malware dropper](https://medium.com/@FeintBE/workshop-map-for-meccha-chameleon-is-a-malware-dropper-full-breakdown-d1ac29565265)
- [The Meccha Chameleon Malware Incident](https://www.youtube.com/watch?v=RB9MrJ2fNqE)
- [UE Map Guardian](https://github.com/PotateBulle/UE-Map-Guardian)
- [Universal Meccha Mod Builder](https://github.com/sirLimbs/Universal-Meccha-Mod-Builder)
- [retoc](https://github.com/trumank/retoc)

UE Map Guardian informed the loose-file coverage and several Windows command
indicators. We did not copy its source code.

## Security and license

Report scanner vulnerabilities through
[GitHub Security Advisories](https://github.com/ifBars/UEWorkshopScanner/security/advisories/new).
Do not attach live
malware or private Workshop content to a public issue.

The source code is available under the [MIT License](LICENSE). Binary
distributions containing Epic Games Licensed Technology are also subject to
[BINARY-EULA.txt](BINARY-EULA.txt) and
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).

UEWorkshopScanner is independent and is not affiliated with Epic Games, Valve,
or the developers of MECCHA CHAMELEON.
