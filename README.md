# UEWorkshopScanner

[![CI](https://github.com/ifBars/UEWorkshopScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/ifBars/UEWorkshopScanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Scan Unreal Engine Workshop maps for known malware behavior before they load.

I started UEWorkshopScanner after malicious
[MECCHA CHAMELEON](https://store.steampowered.com/app/4704690/MECCHA_CHAMELEON/)
maps used Blueprint code to download and run malware. Meccha is the first
supported game, with more Unreal Engine games planned as the project grows.

The scanner runs entirely on your computer. It does not upload your maps,
contact a remote service, or execute files found inside a Workshop item.

> [!WARNING]
> UEWorkshopScanner is experimental. A clean result reduces risk, but it cannot
> prove that a Workshop item is safe. Keep Windows Security or another
> antivirus enabled.

## Download

For the easiest setup, download the `desktop-windows-x64` ZIP from the
[experimental release](https://github.com/ifBars/UEWorkshopScanner/releases/tag/v0.1.0-alpha.4).
It contains a simple desktop app and the files needed to read compressed Unreal
Engine content. No command-line setup is required.

The included Oodle decoder has separate Epic Games terms. The desktop app shows
the complete terms during one-time setup and does not activate the decoder
until you accept them.

Advanced testers can download a newer decoder-free build from the
[latest successful GitHub Actions run](https://github.com/ifBars/UEWorkshopScanner/actions/workflows/ci.yml?query=branch%3Amain+is%3Asuccess).
That build requires your own authorized Oodle decoder.

## Scan a MECCHA CHAMELEON map

### Desktop app

1. Extract the complete desktop ZIP.
2. Start `UEWorkshopScanner.exe`.
3. Review the one-time bundled-binary terms.
4. Drop a Workshop map folder onto the window, or select **Browse for folder**.
5. Select **Scan this map** and follow the displayed recommendation.

Meccha maps are normally stored here:

```text
<SteamLibrary>\steamapps\workshop\content\4704690\<WorkshopItemId>
```

### Command-line scanner

1. Extract the downloaded ZIP.
2. Open the extracted folder in Windows Terminal.
3. Review and accept the included binary terms:

```powershell
.\ue-workshop-scanner.exe --licenses
.\ue-workshop-scanner.exe --accept-eula
```

4. Find the Workshop map you want to scan.

5. Run the scanner with the map folder:

```powershell
.\ue-workshop-scanner.exe "D:\SteamLibrary\steamapps\workshop\content\4704690\1234567890" `
  --game meccha-chameleon `
  --summary
```

Replace the example path and Workshop ID with the map on your computer.

### Understand the result

The first line gives the simplest answer:

```text
block: no
verdict: allow
complete: yes
message: No known malicious behavior was detected
rules triggered: none
```

| Result | What to do |
| --- | --- |
| `allow` | No current rule matched. You can continue, but normal caution still applies. |
| `review` | Do not open the map until someone has reviewed the report. |
| `block` | Remove or unsubscribe from the map. Do not open it. |
| `incomplete` | The scanner could not inspect everything. Treat the map as blocked. |

Use `--output scan-result.txt` to save the summary:

```powershell
.\ue-workshop-scanner.exe "D:\path\to\WorkshopItem" `
  --game meccha-chameleon `
  --summary `
  --output ".\scan-result.txt"
```

## Automatic protection for Meccha

The alpha.2 GitHub pre-release includes an experimental UE4SS integration. It
watches Meccha's map-loading path and scans each Workshop item before Unreal
Engine mounts it.

- Clean maps continue loading after the scan.
- Suspicious or incomplete maps remain blocked.
- If Meccha cannot safely cancel the host's map request, the integration closes
  the game before the map loads.
- A Windows warning explains what happened and shows where the scan report was
  saved.
- Protection starts automatically. There are no hotkeys to press.

Download the `meccha-mod-windows-x64` ZIP from the
[alpha.2 release](https://github.com/ifBars/UEWorkshopScanner/releases/tag/v0.1.0-alpha.2)
and follow `README-FIRST.txt`. The first launch verifies the exact tested game
and UE4SS versions, opens the bundled binary terms for review, and activates
protection only after acceptance.

## What the scanner checks

UEWorkshopScanner looks for behavior used by the documented Meccha malware
dropper, including:

- Blueprint code that runs automatically and writes files;
- PowerShell or command-shell download chains;
- encoded commands and policy bypasses;
- scripts or executables hidden inside a Workshop item;
- files disguised with an incorrect extension;
- suspicious combinations of file writes, URLs, and process launches.

A single word such as `PowerShell` or a normal `BeginPlay` event does not block
a map by itself. Blocking rules require related behavior in the same asset.

## What it does not do

UEWorkshopScanner does not:

- run the map, its scripts, or bundled executables;
- start Unreal Engine or `UnrealPak.exe`;
- upload the map or scan report;
- replace your antivirus;
- inspect encrypted containers without an authorized key;
- fully inspect legacy `.pak` content yet.

The scanner currently supports UE5 IoStore content stored in `.utoc` and
`.ucas` files. It also checks loose files placed beside those containers.

## Frequently asked questions

### Why did my game close?

The automatic Meccha integration closes the game only when it cannot safely
allow a map to load. A warning should show the Workshop item ID, the result,
and the saved report path.

### Does an allow result mean the map is safe?

No. It means the scan completed and no current rule matched. New techniques,
encrypted content, parser limitations, or native-code attacks may not be
detected.

### Does the scanner need administrator access?

No. Run it as your normal Windows user.

### Does it send my Workshop maps anywhere?

No. Scanning is local, and the CLI has no network client.

### Can I request support for another game?

Yes. Open a
[game-support request](https://github.com/ifBars/UEWorkshopScanner/issues/new?template=game-support.yml)
with the game name, Steam App ID, Unreal Engine version if known, and a
description of its mod format.

Do not upload private maps, proprietary game files, decryption keys, or malware
to a public issue.

## For developers and contributors

<details>
<summary>Build from source</summary>

Install Rust 1.88 or newer:

```powershell
git clone https://github.com/ifBars/UEWorkshopScanner.git
cd UEWorkshopScanner
cargo build --locked --release
```

Source builds do not download or include Oodle. Supply an authorized decoder
and its SHA-256 digest when scanning compressed content:

```powershell
.\target\release\ue-workshop-scanner.exe "D:\path\to\WorkshopItem" `
  --oodle-path "D:\path\to\oo2core_9_win64.dll" `
  --oodle-sha256 "<sha256>" `
  --game meccha-chameleon `
  --summary
```

</details>

<details>
<summary>Machine-readable reports</summary>

JSON is the default output for launchers, mod managers, and game integrations:

```powershell
.\ue-workshop-scanner.exe "D:\path\to\WorkshopItem" `
  --game meccha-chameleon `
  --output ".\scan-result.json"
```

Exit codes are stable:

| Verdict | Exit code |
| --- | ---: |
| `allow` | 0 |
| `review` | 2 |
| `block` | 3 |
| `incomplete` or scanner error | 4 |

</details>

<details>
<summary>Contributing</summary>

Run the same checks used by CI:

```powershell
cargo fmt --check
cargo test --workspace --locked
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo +1.88.0 check --workspace --locked --all-targets
```

When `Cargo.lock` changes, install
[cargo-about](https://github.com/EmbarkStudios/cargo-about) and regenerate the
shipped dependency notices:

```powershell
cargo install --locked --features cli cargo-about
.\scripts\generate-third-party-licenses.ps1
```

New blocking rules need an inert positive test, a benign negative test, and a
documented behavior chain. Do not commit malware, private Workshop maps,
proprietary Unreal assets, Oodle binaries, or decryption keys.

Read [CONTRIBUTING.md](CONTRIBUTING.md), the
[architecture](docs/architecture.md), and the
[threat model](docs/threat-model.md) before changing detection or parser
behavior.

</details>

## Research and related work

- [2-Click Remote Code Execution in Meccha Chameleon](https://khaelkugler.com/blogs/meccha_chameleon.html)
- [Workshop map for MECCHA CHAMELEON is a malware dropper](https://medium.com/@FeintBE/workshop-map-for-meccha-chameleon-is-a-malware-dropper-full-breakdown-d1ac29565265)
- [The Meccha Chameleon Malware Incident](https://www.youtube.com/watch?v=RB9MrJ2fNqE)
- [UE Map Guardian](https://github.com/PotateBulle/UE-Map-Guardian)
- [Universal Meccha Mod Builder](https://github.com/sirLimbs/Universal-Meccha-Mod-Builder)
- [retoc](https://github.com/trumank/retoc)

## Security and license

Report scanner vulnerabilities through
[GitHub Security Advisories](https://github.com/ifBars/UEWorkshopScanner/security/advisories/new).
Do not attach live malware or private Workshop content to a public issue.

The source code uses the [MIT License](LICENSE). Binary releases containing
Epic Games Licensed Technology are also subject to
[BINARY-EULA.txt](BINARY-EULA.txt) and
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt). The generated
[THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt) carries the license texts
and attribution for the complete locked Rust dependency graph.

UEWorkshopScanner is independent and is not affiliated with Epic Games, Valve,
or the developers of MECCHA CHAMELEON.
