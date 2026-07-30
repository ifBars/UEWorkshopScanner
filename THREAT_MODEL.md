# Threat model

## Trust boundary

Everything inside a Workshop item is attacker-controlled, including standard
Unreal containers and Blueprint assets. A valid `.pak`, `.utoc`, or `.ucas`
header does not imply benign behavior.

## In scope

- Loose executable/script delivery.
- Disguised executable headers.
- In-process IoStore/Pak inventory and package reading.
- Automatic Blueprint entrypoints.
- Local-file launch through `LaunchURL`.
- User-directory discovery followed by file output.
- Script and JSON/batch polyglot construction.
- PowerShell/cmd download-and-execute behavior.
- Published Meccha Chameleon Blueprint behavior chains.

## Out of scope

- Native code decompilation.
- UE4SS Lua/C++ mods and DLL injection chains.
- Encrypted containers without an authorized key.
- Full Kismet control-flow and data-flow reconstruction.
- Runtime sandboxing or automatic deletion of Workshop subscriptions.
- Treating an `allow` result as proof that an add-on is safe.
- Automatic acquisition of Oodle binaries, mappings, or decryption keys.

## Blocking policy

The scanner blocks only high-confidence combinations such as an automatic
external file-write chain, a local file-launch chain, or a shell downloader.
Individual dual-use Blueprint functions produce a review result rather than a
block. A dangerous loose-file type is independently blocking because Workshop
map content has no legitimate need to deliver Windows scripts or executables.

## Completeness policy

Completeness is not a threat classification. Missing companions, skipped
symlinks, oversized items, read errors, container failures, and a directory
without an IoStore entry point are recorded as structured reasons. Unless a
stronger blocking finding exists, any such reason yields `incomplete`, never
`allow`.
