# MECCHA CHAMELEON UE4SS integration

This integration is the first game adapter for UEWorkshopScanner. It packages
the Rust scanner as a UE4SS Lua mod for both Thunderstore and Nexus Mods.
The package includes `enabled.txt` because profile-managed mods cannot safely
edit the shared UE4SS `Mods.txt` file.

## Current boundary

Version `0.1.0` is deliberately observe-only:

- `Ctrl+Shift+F8` starts the scanner outside the game process;
- `Ctrl+Shift+F9` inventories reflected functions that may expose the
  download-to-map-load boundary;
- no function is hooked;
- no load, mount, travel, or Steam callback is cancelled.

UE4SS Lua can hook existing reflected `UFunction` objects, but that alone does
not prove a pre-hook can cancel an arbitrary side-effecting call. The next
runtime research step is to capture the F9 diagnostic output on the current
game build, trace promising functions, and verify a cancellable predicate or
transition before adding enforcement.

`ExecuteAsync` is used only to keep the external scanner process off the game
thread. It is deprecated in current UE4SS documentation, while the suggested
delayed alternative executes on the game thread and is not suitable for a
blocking child process. A native UE4SS C++ adapter or non-blocking worker bridge
should replace it before a stable release.

## Build packages

```powershell
.\scripts\package-meccha-ue4ss.ps1 `
  -OodlePath "D:\path\to\oo2core_9_win64.dll" `
  -Version "0.1.0"
```

The script creates:

- a Thunderstore ZIP whose root follows Thunderstore's package format;
- a Nexus ZIP containing `Mods/UEWorkshopScanner`;
- SHA-256 files for both archives.

The script performs no uploads and does not include any Workshop maps.

## Runtime validation still required

Before calling this integration protected or publishing it as a blocker:

1. install the generated package in an isolated Thunderstore profile;
2. accept the bundled binary terms;
3. confirm F8 produces a report for installed Workshop content;
4. capture the F9 candidate list from the current game build;
5. reproduce the lobby prompt and download flow with a benign test map;
6. identify and version-gate a transition that can be cancelled before mount;
7. verify `allow`, `review`, `block`, and `incomplete` behavior independently.

Do not test a known malicious map in the game process.
