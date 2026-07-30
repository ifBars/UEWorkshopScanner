# UEWorkshopScanner for MECCHA CHAMELEON

This is an early UE4SS integration for
[UEWorkshopScanner](https://github.com/ifBars/UEWorkshopScanner).

Press `Ctrl+Shift+F8` in game to scan every currently installed MECCHA
CHAMELEON Workshop item. Reports are written to the mod's `reports` directory.

Press `Ctrl+Shift+F9` to write a diagnostic list of reflected Unreal functions
whose names may be related to Workshop downloads, mounting, or map travel.
This can briefly pause the game while UE4SS walks the object registry.

> This prototype observes and scans; it does **not** block a map from loading
> yet. Reliable blocking needs a tested hook between Steam finishing a Workshop
> download and the game mounting or traveling to that map.

The bundled scanner may require one-time acceptance of its binary terms before
the integration can run. Open a terminal in `UEWorkshopScanner/bin`, run
`ue-workshop-scanner.exe --licenses`, then
`ue-workshop-scanner.exe --accept-eula`.

Thunderstore users should install this package through their Meccha Chameleon
profile; its declared dependency supplies the current community UE4SS overlay.
The Nexus archive is a manual UE4SS layout: extract its `Mods` directory into
`Chameleon\Binaries\Win64` after installing a compatible UE4SS build.

Do not upload Workshop maps, scan reports containing private paths, or malware
when reporting an issue.
