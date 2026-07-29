# UEWorkshopScanner

[![CI](https://github.com/ifBars/UEWorkshopScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/ifBars/UEWorkshopScanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)

UEWorkshopScanner is a local static malware scanner for Unreal Engine Workshop
content. It opens UE5 IoStore packages in-process, scans cooked assets for
correlated Blueprint behavior, and returns a machine-readable verdict before
the add-on is loaded by a game.

The initial rules target the attack chain used in malicious
[MECCHA CHAMELEON](https://store.steampowered.com/app/4704690/MECCHA_CHAMELEON/)
Workshop maps: automatic Blueprint execution, external file writes, script
construction, hidden shell execution, and download behavior.

> [!IMPORTANT]
> This is an early static-analysis tool, not an antivirus replacement. An
> `allow` verdict means no current rule matched and the scan completed; it does
> not prove that an add-on is safe.

## What it detects

- automatic `BeginPlay` behavior reaching file or URL operations;
- writes into user-controlled directories, especially script extensions;
- PowerShell and command-shell download-and-execute chains;
- JSON/batch polyglot construction;
- hidden shell execution;
- the documented Meccha Chameleon dropper behavior chain;
- retained historical RCE fixture names.

Rules correlate markers within the same cooked asset. Individual dual-use
Blueprint functions do not block a map by themselves.

## Quick start

Windows archives will be published through
[GitHub Releases](../../releases). Until the first archive is available, build
the CLI from source as described below. Extract the entire archive, then scan a
Workshop package through its `.utoc` entry point:

```powershell
.\ue-workshop-scanner.exe "D:\path\to\WorkshopItem\Map-Windows.utoc"
```

The release archive keeps the scanner and its pinned Oodle decoder together.
On first use, review and accept the bundled binary terms:

```powershell
.\ue-workshop-scanner.exe --licenses
.\ue-workshop-scanner.exe "D:\path\to\Map-Windows.utoc" --accept-eula
```

Acceptance is stored once in the user's local configuration directory.
Interactive use prompts instead of requiring the flag.

### Read the result

The CLI writes a JSON report to standard output.

| Verdict | Exit code | Meaning |
| --- | ---: | --- |
| `allow` | 0 | Scan completed and no current rule matched |
| `review` | 2 | Suspicious dual-use behavior needs review |
| `block` | 3 | A high-confidence malicious behavior chain matched |
| `incomplete` | 4 | Some content could not be safely inspected |

Example:

```json
{
  "verdict": "block",
  "complete": true,
  "chunks_seen": 2088,
  "chunks_scanned": 2088,
  "findings": [
    {
      "rule_id": "UWS108",
      "title": "Meccha Chameleon Blueprint dropper behavior chain",
      "severity": "critical",
      "blocking": true
    }
  ]
}
```

## Safety properties

- no network client and no runtime dependency downloads;
- no Unreal Engine or `UnrealPak.exe` requirement;
- no extraction of scanned assets to disk;
- exact Oodle redistributable hash allowlist;
- configurable per-chunk size cap;
- incomplete analysis can never produce `allow`;
- deterministic artifact and finding order;
- Workshop packages, cooked assets, and malware samples are excluded from Git.

The native decoder and container parser still process attacker-controlled
input. The planned desktop integration should run this CLI as an unprivileged,
resource-limited worker. See [THREAT_MODEL.md](THREAT_MODEL.md) and
[ARCHITECTURE.md](ARCHITECTURE.md).

## Build from source

Requirements:

- current stable Rust toolchain with the 2024 edition;
- an authorized Oodle Data 2.9.10 Windows decoder for Oodle-compressed content.

```powershell
cargo build --locked --release
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Use a separately obtained decoder by providing both its path and digest:

```powershell
.\target\release\ue-workshop-scanner.exe `
  "D:\path\to\Map-Windows.utoc" `
  --oodle-path "D:\path\to\oo2core_9_win64.dll" `
  --oodle-sha256 "<sha256>"
```

Run `ue-workshop-scanner --help` for the complete CLI reference.

## Release packaging

Maintainers can build a self-contained Windows archive from an approved local
Epic redistributable:

```powershell
.\scripts\package-windows-release.ps1 `
  -OodlePath "D:\path\to\Epic\win\redist\oo2core_9_win64.dll" `
  -Version "0.1.0"
```

The packager performs no downloads. It validates the decoder hash, builds with
`Cargo.lock`, includes the binary EULA and notices, and generates per-file and
archive SHA-256 checksums. See
[OODLE_DISTRIBUTION.md](OODLE_DISTRIBUTION.md) for the distribution rationale
and residual licensing risk.

## Current limitations

- UE5 IoStore `.utoc`/`.ucas` packages are the current end-user path.
- Encrypted containers require an authorized key and are not currently
  supported.
- Marker correlation does not yet reconstruct complete Kismet control flow.
- Native C++ plugins, UE4SS mods, and DLL injection chains are out of scope.
- Detection is currently focused on published Meccha Chameleon behavior.

## Research basis

- [2-Click Remote Code Execution in Meccha Chameleon](https://khaelkugler.com/blogs/meccha_chameleon.html)
- [Workshop map for MECCHA CHAMELEON is a malware dropper](https://medium.com/@FeintBE/workshop-map-for-meccha-chameleon-is-a-malware-dropper-full-breakdown-d1ac29565265)
- [The Meccha Chameleon Malware Incident](https://www.youtube.com/watch?v=RB9MrJ2fNqE)
- [retoc](https://github.com/trumank/retoc)

No malicious sample, private Workshop package, or proprietary Unreal asset is
included in this repository.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing rules or parser
behavior. Please report scanner vulnerabilities privately through
[GitHub Security Advisories](../../security/advisories/new); do not attach live
malware to a public issue.

## License and trademarks

UEWorkshopScanner source code is available under the [MIT License](LICENSE).
Compiled distributions containing Epic Games Licensed Technology are also
subject to [BINARY-EULA.txt](BINARY-EULA.txt) and
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).

UEWorkshopScanner is independent and is not affiliated with, sponsored by, or
endorsed by Epic Games, Valve, or the developers of MECCHA CHAMELEON.
