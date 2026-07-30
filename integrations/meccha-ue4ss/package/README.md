# UEWorkshopScanner for MECCHA CHAMELEON

This is an early UE4SS integration for
[UEWorkshopScanner](https://github.com/ifBars/UEWorkshopScanner).

No hotkeys or manual activation are required. The integration installs its
Workshop mount gate automatically after its one-time setup and compatibility
checks pass.

The integration holds Meccha's IoStore mount while the external scanner checks
the individual Workshop item. A clean result releases the mount. A block,
review, incomplete scan, or scanner error keeps the content from mounting,
closes the game to stop its retry loop, and displays a native Windows warning
with the Workshop item ID, decision, and report path.

> Enforcement is experimental. Only use it with the documented supported game
> and UE4SS versions.

On first launch, the complete bundled binary terms open in Notepad. Close
Notepad after reviewing them, then accept or decline the native setup prompt.
Protection activates only after acceptance. Later launches reuse the recorded
acceptance.

Thunderstore users should install this package through their Meccha Chameleon
profile; its declared dependency supplies the current community UE4SS overlay.
The GitHub manual archive includes the exact tested UE4SS build and can be
extracted directly into the MECCHA CHAMELEON installation folder.

This build supports:

- MECCHA CHAMELEON 3.1.0, executable SHA-256
  `001b329edb0f37b6d3157d8334edbd58a83d092d9748f9439dd1b59f2cace36a`;
- UE4SS 3.0.1 Beta #0, Git `0196ef29`, DLL SHA-256
  `df9e6e9a2280972b1c28ce590700feacc752b447204f8baadeb95f5776957055`.

Other builds receive a visible compatibility warning and protection stays
inactive.

Do not upload Workshop maps, scan reports containing private paths, or malware
when reporting an issue.
