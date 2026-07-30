# Native pre-mount diagnostic

This experimental UE4SS C++ mod observes Meccha Chameleon's native workshop
mount path. It exists because the game's client loader calls the C++
implementation directly, bypassing UE4SS's reflected `UFunction` hook.

The diagnostic is intentionally narrow:

- supports only the executable fingerprint recorded in `src/main.cpp`;
- verifies both the executable SHA-256 and original call-site bytes;
- logs the workshop item ID and pak name immediately before mounting;
- always calls the original mount implementation and does not block content;
- restores the original call instruction when UE4SS uninstalls the mod.

The build uses a small ABI-only lifecycle shim pinned to UE4SS 3.0.1. It does
not require or redistribute UE4SS's private Unreal headers.

Build with Visual Studio 2022:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Install `build/Release/main.dll` as:

```text
Mods/
  UEWorkshopScannerNative/
    enabled.txt
    dlls/
      main.dll
```

The runtime log is written to
`Mods/UEWorkshopScannerNative/native-hook.log`.

