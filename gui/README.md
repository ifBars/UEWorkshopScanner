# UEWorkshopScanner Desktop Prototype

This is a player-facing Dioxus desktop frontend for the shared
`ue-workshop-scanner` Rust library.

The GUI contains no detection rules. It runs the public scanner facade on a
background worker, writes a JSON report under the current user's local
application-data directory, and maps the same typed report used by the CLI into
a simpler result screen.

## Prototype scope

- choose or drop a Workshop item folder;
- run the Meccha Chameleon game profile;
- show Allow, Review, Block, or Incomplete in plain language;
- list triggered rules and completeness reasons;
- reveal the saved JSON report in Explorer.

The complete GitHub prerelease package includes the approved Oodle decoder,
full bundled-binary terms, one-time in-app acceptance, licenses, notices, and
SHA-256 manifests.

## Run locally

From the repository root:

```powershell
cargo run -p ue-workshop-scanner-gui
```

No separate CLI installation or environment variable is required.
