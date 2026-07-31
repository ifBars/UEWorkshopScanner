[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $OodlePath,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string] $Ue4ssOverlayPath,

    [string] $Version = "0.1.0-alpha.4",

    [string] $OutputDirectory = (Join-Path $PSScriptRoot "..\artifacts\meccha-ue4ss")
)

$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$templateRoot = Join-Path $projectRoot "integrations\meccha-ue4ss\package"
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$dependencyOutput = Join-Path $outputRoot "scanner"
$scannerStage = Join-Path $dependencyOutput "UEWorkshopScanner-$Version-cli-windows-x64"
$thunderstoreStage = Join-Path $outputRoot "UEWorkshopScanner-$Version-thunderstore"
$nexusStage = Join-Path $outputRoot "UEWorkshopScanner-$Version-nexus"
$manualStage = Join-Path $outputRoot "UEWorkshopScanner-$Version-meccha-mod-windows-x64"
$thunderstoreArchive = "$thunderstoreStage.zip"
$nexusArchive = "$nexusStage.zip"
$manualArchive = "$manualStage.zip"
$expectedUe4ssSha256 = "df9e6e9a2280972b1c28ce590700feacc752b447204f8baadeb95f5776957055"
$expectedProxySha256 = "19a9be77367c22bc8a6b90faad3573f8f85c7612db574f7948c4cbaf37cfa831"

function Write-StageChecksums {
    param([Parameter(Mandatory = $true)][string] $Root)

    $rootPrefix = [System.IO.Path]::GetFullPath($Root).TrimEnd("\") + "\"
    $lines = Get-ChildItem -LiteralPath $Root -Recurse -File |
        Where-Object { $_.Name -ne "SHA256SUMS" } |
        Sort-Object FullName |
        ForEach-Object {
            if (-not $_.FullName.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Checksum input escaped the staging directory: $($_.FullName)"
            }
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $relative = $_.FullName.Substring($rootPrefix.Length).Replace("\", "/")
            "$hash  $relative"
        }
    [System.IO.File]::WriteAllLines((Join-Path $Root "SHA256SUMS"), $lines)
}

& (Join-Path $PSScriptRoot "package-windows-release.ps1") `
    -OodlePath $OodlePath `
    -Version $Version `
    -OutputDirectory $dependencyOutput
if ($LASTEXITCODE -ne 0) {
    throw "Windows scanner packaging failed with exit code $LASTEXITCODE."
}

foreach ($target in @($thunderstoreStage, $nexusStage, $manualStage)) {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}
foreach ($archive in @($thunderstoreArchive, $nexusArchive, $manualArchive)) {
    if (Test-Path -LiteralPath $archive) {
        Remove-Item -LiteralPath $archive -Force
    }
}

New-Item -ItemType Directory -Path $thunderstoreStage | Out-Null
Copy-Item -LiteralPath (Join-Path $templateRoot "manifest.json") -Destination $thunderstoreStage
Copy-Item -LiteralPath (Join-Path $templateRoot "README.md") -Destination $thunderstoreStage
Copy-Item -LiteralPath (Join-Path $templateRoot "CHANGELOG.md") -Destination $thunderstoreStage
Copy-Item -LiteralPath (Join-Path $templateRoot "icon.png") -Destination $thunderstoreStage
Copy-Item -LiteralPath (Join-Path $templateRoot "UEWorkshopScanner") `
    -Destination $thunderstoreStage -Recurse

$manifestPath = Join-Path $thunderstoreStage "manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$manifest.version_number = $Version -replace '-.*$', ''
$manifestJson = $manifest | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($manifestPath, $manifestJson + "`n")

$thunderstoreBin = Join-Path $thunderstoreStage "UEWorkshopScanner\bin"
New-Item -ItemType Directory -Path $thunderstoreBin | Out-Null
Copy-Item -Path (Join-Path $scannerStage "*") -Destination $thunderstoreBin

$nexusMod = Join-Path $nexusStage "Mods\UEWorkshopScanner"
New-Item -ItemType Directory -Path $nexusMod -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $templateRoot "UEWorkshopScanner\Scripts") `
    -Destination $nexusMod -Recurse
Copy-Item -LiteralPath (Join-Path $templateRoot "UEWorkshopScanner\enabled.txt") `
    -Destination $nexusMod
Copy-Item -LiteralPath (Join-Path $templateRoot "README.md") `
    -Destination (Join-Path $nexusMod "README.md")
$nexusBin = Join-Path $nexusMod "bin"
New-Item -ItemType Directory -Path $nexusBin | Out-Null
Copy-Item -Path (Join-Path $scannerStage "*") -Destination $nexusBin

foreach ($required in @(
    "dwmapi.dll",
    "UE4SS.dll",
    "UE4SS-settings.ini",
    "LICENSE"
)) {
    $requiredPath = Join-Path $Ue4ssOverlayPath $required
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "The UE4SS overlay is missing $requiredPath"
    }
}
$signaturesPath = Join-Path $Ue4ssOverlayPath "UE4SS_Signatures"
if (-not (Test-Path -LiteralPath $signaturesPath -PathType Container)) {
    throw "The UE4SS overlay is missing $signaturesPath"
}
$actualUe4ssSha256 = (Get-FileHash -LiteralPath (Join-Path $Ue4ssOverlayPath "UE4SS.dll") -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualUe4ssSha256 -ne $expectedUe4ssSha256) {
    throw "UE4SS.dll does not match the tested build; got SHA-256 $actualUe4ssSha256."
}
$actualProxySha256 = (Get-FileHash -LiteralPath (Join-Path $Ue4ssOverlayPath "dwmapi.dll") -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualProxySha256 -ne $expectedProxySha256) {
    throw "dwmapi.dll does not match the tested build; got SHA-256 $actualProxySha256."
}

$manualWin64 = Join-Path $manualStage "Chameleon\Binaries\Win64"
$manualMod = Join-Path $manualWin64 "Mods\UEWorkshopScanner"
$manualBin = Join-Path $manualMod "bin"
$manualLicenses = Join-Path $manualStage "LICENSES"
New-Item -ItemType Directory -Path $manualWin64 -Force | Out-Null
New-Item -ItemType Directory -Path $manualMod -Force | Out-Null
New-Item -ItemType Directory -Path $manualBin -Force | Out-Null
New-Item -ItemType Directory -Path $manualLicenses -Force | Out-Null

Copy-Item -LiteralPath (Join-Path $Ue4ssOverlayPath "dwmapi.dll") -Destination $manualWin64
Copy-Item -LiteralPath (Join-Path $Ue4ssOverlayPath "UE4SS.dll") -Destination $manualWin64
Copy-Item -LiteralPath (Join-Path $Ue4ssOverlayPath "UE4SS-settings.ini") -Destination $manualWin64
Copy-Item -LiteralPath $signaturesPath -Destination $manualWin64 -Recurse
Copy-Item -LiteralPath (Join-Path $templateRoot "UEWorkshopScanner\Scripts") `
    -Destination $manualMod -Recurse
Copy-Item -LiteralPath (Join-Path $templateRoot "UEWorkshopScanner\enabled.txt") `
    -Destination $manualMod
Copy-Item -LiteralPath (Join-Path $templateRoot "README.md") `
    -Destination (Join-Path $manualMod "README.md")
Copy-Item -Path (Join-Path $scannerStage "*") -Destination $manualBin
Copy-Item -LiteralPath (Join-Path $projectRoot "integrations\meccha-ue4ss\MANUAL-INSTALL.txt") `
    -Destination (Join-Path $manualStage "README-FIRST.txt")
Copy-Item -LiteralPath (Join-Path $projectRoot "BINARY-EULA.txt") -Destination $manualStage
Copy-Item -LiteralPath (Join-Path $projectRoot "THIRD_PARTY_NOTICES.txt") -Destination $manualStage
Copy-Item -LiteralPath (Join-Path $projectRoot "THIRD_PARTY_LICENSES.txt") -Destination $manualStage
Copy-Item -LiteralPath (Join-Path $projectRoot "LICENSE") `
    -Destination (Join-Path $manualLicenses "UEWorkshopScanner-MIT.txt")
Copy-Item -LiteralPath (Join-Path $Ue4ssOverlayPath "LICENSE") `
    -Destination (Join-Path $manualLicenses "RE-UE4SS-MIT.txt")

Write-StageChecksums -Root $thunderstoreStage
Write-StageChecksums -Root $nexusStage
Write-StageChecksums -Root $manualStage

Compress-Archive -Path (Join-Path $thunderstoreStage "*") `
    -DestinationPath $thunderstoreArchive -CompressionLevel Optimal
Compress-Archive -Path (Join-Path $nexusStage "*") `
    -DestinationPath $nexusArchive -CompressionLevel Optimal
Compress-Archive -Path (Join-Path $manualStage "*") `
    -DestinationPath $manualArchive -CompressionLevel Optimal

foreach ($archive in @($thunderstoreArchive, $nexusArchive, $manualArchive)) {
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $line = "$hash  $([System.IO.Path]::GetFileName($archive))`n"
    [System.IO.File]::WriteAllText("$archive.sha256", $line)
    Write-Host "Created $archive"
    Write-Host "SHA-256 $hash"
}
