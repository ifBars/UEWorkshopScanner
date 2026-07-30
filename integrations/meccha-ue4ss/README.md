# MECCHA CHAMELEON UE4SS integration

This integration is the first game adapter for UEWorkshopScanner. It packages
the Rust scanner as a UE4SS Lua mod for both Thunderstore and Nexus Mods.
The package includes `enabled.txt` because profile-managed mods cannot safely
edit the shared UE4SS `Mods.txt` file.

## Current boundary

The distributable integration has a tested reflected pre-mount boundary:

- startup automatically hooks Meccha's
  `MountIoStoreAndGetLevelsFromAssetRegistry` call and diagnostic Workshop
  lifecycle;
- if the function is not resident yet, a one-second delayed loop retries until
  registration succeeds and then cancels itself;
- the mount path is replaced with an invalid path while the asynchronous scan
  is pending;
- `allow` restores the original path on the next retry;
- `review`, `block`, `incomplete`, and scanner errors remain denied;
- a terminal denial closes the game to stop Meccha's mount retry loop, then
  shows a native Windows warning containing the item ID and report path.

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

Before calling this integration stable:

1. install the generated package in an isolated Thunderstore profile;
2. accept the bundled binary terms;
3. confirm the UE4SS log reports `Protection active` without any user input;
4. reproduce the client download flow with a benign test map;
5. verify the clean scan delays and then permits the mount;
6. verify the native warning and forced-close fallback with an inert blocking
   fixture;
7. verify `review`, `block`, and `incomplete` independently;
8. add exact game-version gating before stable release.

Do not test a known malicious map in the game process.
