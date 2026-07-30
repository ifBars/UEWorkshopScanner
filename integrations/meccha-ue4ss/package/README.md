# UEWorkshopScanner for MECCHA CHAMELEON

This is an early UE4SS integration for
[UEWorkshopScanner](https://github.com/ifBars/UEWorkshopScanner).

No hotkeys or manual activation are required. The integration installs its
Workshop mount gate automatically when the game starts. If Meccha's reflected
mount function is not available yet, it retries in the background until the
gate is active and then stops retrying.

The integration holds Meccha's IoStore mount while the external scanner checks
the individual Workshop item. A clean result releases the mount. A block,
review, incomplete scan, or scanner error keeps the content from mounting,
closes the game to stop its retry loop, and displays a native Windows warning
with the Workshop item ID, decision, and report path.

> Enforcement is experimental. Only use it with the documented supported game
> and UE4SS versions.

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
