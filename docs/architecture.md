# Architecture

UEWorkshopScanner is a Rust CLI built around an in-process, fail-closed scan
pipeline:

```mermaid
flowchart LR
    Item["Workshop item directory or .utoc"] --> Envelope["Envelope inventory"]
    Envelope --> Loose["Bounded loose-file reads"]
    Envelope --> Containers[".utoc + .ucas"]
    Containers --> Retoc["retoc / repak"]
    Oodle["Pinned Oodle decoder"] --> Retoc
    Retoc --> Chunks["Bounded parallel chunk reads"]
    Loose --> Markers["Normalized markers"]
    Chunks --> Markers
    Markers --> Rules["Foundational behavior rules"]
    Rules --> Families["Threat-family classifier"]
    Families --> Disposition["Disposition classifier"]
    Completeness["Independent completeness state"] --> Disposition
    Disposition --> Verdict["JSON report + process exit code"]
```

## Container layer

[retoc](https://github.com/trumank/retoc) is pinned to commit
`d034ade1ae8117d4786eaf6b0418d4cf48474d7f`. It exposes virtual paths and
decompressed IoStore chunks without launching Unreal Engine or extracting
assets to disk.

retoc's upstream Oodle adapter can download a native decoder when one is
missing. A security scanner should not silently fetch and load native code, so
this repository replaces it with `vendor/oodle_loader_safe`. The replacement:

- contains no HTTP dependency;
- accepts only an explicit local path and SHA-256 digest;
- is initialized before worker threads start;
- fails when the decoder is unavailable or its digest differs.

Official Windows archives place an approved decoder beside the executable. The
CLI detects that file by name, independently hashes it, and accepts only the
reviewed digests in `src/oodle.rs`.

## Source layout

The Cargo package contains one library target and one thin binary target:

```text
src/main.rs          process entry point
src/lib.rs           library crate root
src/cli.rs           argument and output contract
src/scanner.rs       scan orchestration
src/envelope.rs      Workshop item discovery and loose files
src/container.rs     IoStore reads
src/markers.rs       byte-to-marker normalization
src/rules.rs         foundational findings
src/threat_intel.rs  family and disposition classification
src/model.rs         report types
src/oodle.rs         decoder and license boundary
src/hashing.rs       streaming file hashes
```

The binary calls the library's CLI entry point and contains no scanner logic.
This keeps process concerns out of the detection pipeline and leaves one place
to add a stable integration API later.

## Scan pipeline

1. Inventory a Workshop directory, or validate a direct `.utoc` input.
2. Resolve and verify the Oodle decoder when required.
3. Inspect bounded loose files without loading or executing them.
4. Open discovered IoStore containers through retoc.
5. Read and scan chunks in parallel through Rayon's bounded worker pool.
6. Decode ASCII plus aligned and unaligned UTF-16LE/UTF-16BE text views.
7. Assign normalized behavior markers.
8. Correlate markers within each artifact into foundational findings.
9. Match finding combinations to named threat-family variants.
10. Derive a final disposition separately from analysis completeness.
11. Emit deterministic JSON and a verdict-specific process exit code.

The collected chunk order is retained when parallel results are joined, so the
same input produces stable artifact and finding order.

## Completeness policy

`allow` is valid only when every non-empty chunk is read within the configured
size limit. A skipped oversized chunk, parser failure, missing decoder, missing
companion file, or unsupported container makes the run incomplete.

The current implementation returns errors as exit code `4` and never converts a
partial scan into `allow`.

## Detection model

Rules are intentionally based on correlated behavior rather than isolated
strings. For example:

- `BeginPlay` alone is ordinary game behavior.
- `ToFile` alone may be legitimate serialization.
- `powershell` in documentation is not a dropper.
- automatic execution plus user-directory discovery, script output, shell
  launch, and downloader markers is a high-confidence chain.

The pipeline follows the same layered principle as MLVScan: rules preserve
low-level signals, threat intelligence groups those signals into named
behavior variants, and disposition decides whether users should allow, review,
or block. Analysis completeness remains independent so missing coverage cannot
be mistaken for a clean result.

This reduces obvious false positives while preserving useful evidence in the
JSON report. It is still serialized-marker analysis, not full Kismet
control-flow reconstruction.

## Supply-chain boundary

- `Cargo.lock` is committed.
- retoc is pinned to an exact Git revision.
- upstream automatic Oodle downloading is removed.
- release packaging accepts only reviewed decoder hashes.
- release ZIPs include file-level and archive-level SHA-256 checksums.
- proprietary decoders, Workshop packages, and cooked Unreal assets are never
  committed.

See [Oodle distribution](oodle-distribution.md) for the Oodle distribution
decision and the [threat model](threat-model.md) for attacker-controlled input
boundaries.

## Future desktop integration

A graphical frontend should treat this CLI as a disposable worker rather than
linking the parser directly into the UI process. The worker should run:

- without network access;
- without administrator privileges;
- with read-only access to the selected Workshop item;
- under memory, CPU-time, and output-size limits;
- with a fresh process for each scan.

That boundary limits the impact of a future parser or native decompressor
vulnerability while keeping the CLI useful by itself.
