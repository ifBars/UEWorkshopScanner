# Oodle distribution decision

Research date: 2026-07-29

This is an engineering licensing assessment, not legal advice.

## Recommendation

Keep the scanner source under MIT while the Windows distribution depends on a
bundled proprietary Oodle decoder. GPL-3.0 would introduce a separate linking
and distribution question unless the project added a suitable exception or
received qualified legal guidance.

Project policy treats the unmodified Epic Oodle 2.9.10 Windows redistributable
as object code incorporated into, and inseparable from, the compiled scanner
Product under Section 4 of the Unreal Engine EULA. Reassess this interpretation
before monetizing the scanner, changing how the DLL is packaged or exposed, or
including other Unreal Engine components.

The intended release layout would be:

```text
UEWorkshopScanner-cli-windows-x64/
  ue-workshop-scanner.exe
  oo2core_9_win64.dll
  BINARY-EULA.txt
  THIRD_PARTY_NOTICES.txt
  LICENSE
  README.md
  SHA256SUMS
```

The scanner recognizes only these two tested Epic Oodle 2.9.10 redistributable
builds:

```text
6f5d41a7892ea6b2db420f2458dad2f84a63901c9a93ce9497337b16c195f457
111a505e64a3bf1b89c05aab2dd16306bc2267a5ea3f0c9722a3b6152091ce1c
```

The first build successfully decoded all 2,088 chunks in the original UE 5.6
inert fixture and reproduced UWS103 through UWS108. The second is the
Authenticode-valid Epic Games build currently installed at UE 5.6's canonical
`Sdk/2.9.10/win/redist` path; it decoded all 2,087 chunks in the current GTA
apartment package with no skipped chunks. Both use the Oodle 2.9.10 ABI
expected by retoc's upstream loader.

The release must include `BINARY-EULA.txt` and `THIRD_PARTY_NOTICES.txt`. The
CLI must expose those terms through `--licenses`, require one-time acceptance
when it uses the bundled decoder, and support explicit `--accept-eula` for
non-interactive use. Binary EULA version 2 also states that the scanner can
produce false positives, false negatives, incomplete results, or errors; does
not replace antivirus or backups; provides no security guarantee; and limits
warranties and liability only to the extent permitted by applicable law.

## Why permission is plausible

The current Unreal Engine EULA defines a Product broadly enough to include a
project that combines Licensed Technology with other software. It permits
distribution of Licensed Technology in object code as an inseparable part of a
Product, subject to an end-user license agreement that disclaims Unreal-related
warranties and liabilities.

The scanner is not used to develop a standalone Unreal product, so it should
not normally meet the EULA's definition of an Engine Tool. A free CLI also
appears to fit the indirect-revenue royalty-free category. The standard
personal/indie seat exception applies while the relevant corporate group
remains below the EULA's stated revenue threshold.

Epic's dependency layout explicitly places this build under:

```text
Engine/Source/Programs/Shared/EpicGames.Oodle/Sdk/2.9.10/win/redist/
```

The adjacent DLL is treated as inseparable in the product sense: the release
archive, executable, pinned decoder, notices, and acceptance flow are one
distribution, and the decoder is exposed only to the scanner's internal
decompression path. This remains an engineering interpretation rather than a
legal opinion; written Epic/RAD confirmation would still reduce residual risk.

## Why other acquisition paths are rejected

- Do not download from `WorkingRobot/OodleUE` at runtime. The repository mirrors
  Epic dependency artifacts, contains no independent license grant, and its
  maintainer explicitly acknowledges that Epic or RAD may object.
- Do not extract the DLL from Warframe, another installed game, or a Steam
  depot. A game's right to distribute Oodle does not transfer to this project.
- Do not use generic DLL download sites.
- Do not restore retoc's automatic downloader. A security scanner should not
  silently fetch and load an unsigned native dependency.
- Do not adopt `powzix/ooz` as-is. Its README says it is not fuzz-safe, and the
  repository has no root license file even though individual sources contain
  GPL notices. It would also create EULA/GPL compatibility questions if mixed
  with an Epic Oodle build.

retoc's own v0.1.5 Windows release contains only `retoc.exe`, `README.md`, and
`LICENSE`; it does not bundle Oodle.

## Optional confirmation request for Epic/RAD

Submit this through the Epic Developer Support category for RAD Game Tools or
Unreal Engine:

> We are developing a free, open-source Rust security scanner for
> user-generated Unreal Engine Workshop content. The scanner does not contain
> Unreal Editor or Developer modules and is not used to create Unreal products.
> It uses Oodle Data only to decompress attacker-controlled Pak/IoStore blocks
> for static malware analysis.
>
> May we distribute the unmodified Windows Oodle 2.9.10 redist binary from
> `Engine/Source/Programs/Shared/EpicGames.Oodle/Sdk/2.9.10/win/redist/`
> alongside our compiled scanner in a GitHub Release ZIP under the standard
> Unreal Engine EULA? If yes, please confirm the required end-user EULA,
> attribution, notices, and whether an adjacent DLL counts as object code
> incorporated as an inseparable part of the Product.

Keep the written response with the project's release-compliance records.

## Primary sources

- Unreal Engine EULA:
  https://www.unrealengine.com/eula/unreal
- Epic Oodle Data documentation:
  https://dev.epicgames.com/documentation/en-us/unreal-engine/oodle-data
- Epic Developer Support:
  https://dev.epicgames.com/support
- retoc v0.1.5 release:
  https://github.com/trumank/retoc/releases/tag/v0.1.5
- OodleUE mirror and its EULA warning:
  https://github.com/WorkingRobot/OodleUE
- ooz safety warning:
  https://github.com/powzix/ooz
- GNU GPL FAQ on GPL-incompatible libraries:
  https://www.gnu.org/licenses/gpl-faq.html#GPLIncompatibleLibs
