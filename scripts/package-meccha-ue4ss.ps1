[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $OodlePath,

    [string] $Version = "0.1.0",

    [string] $OutputDirectory = (Join-Path $PSScriptRoot "..\artifacts\meccha-ue4ss")
)

$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$templateRoot = Join-Path $projectRoot "integrations\meccha-ue4ss\package"
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$dependencyOutput = Join-Path $outputRoot "scanner"
$scannerStage = Join-Path $dependencyOutput "UEWorkshopScanner-$Version-windows-x64"
$thunderstoreStage = Join-Path $outputRoot "UEWorkshopScanner-$Version-thunderstore"
$nexusStage = Join-Path $outputRoot "UEWorkshopScanner-$Version-nexus"
$thunderstoreArchive = "$thunderstoreStage.zip"
$nexusArchive = "$nexusStage.zip"

& (Join-Path $PSScriptRoot "package-windows-release.ps1") `
    -OodlePath $OodlePath `
    -Version $Version `
    -OutputDirectory $dependencyOutput
if ($LASTEXITCODE -ne 0) {
    throw "Windows scanner packaging failed with exit code $LASTEXITCODE."
}

foreach ($target in @($thunderstoreStage, $nexusStage)) {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}
foreach ($archive in @($thunderstoreArchive, $nexusArchive)) {
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
$manifest.version_number = $Version
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

Compress-Archive -Path (Join-Path $thunderstoreStage "*") `
    -DestinationPath $thunderstoreArchive -CompressionLevel Optimal
Compress-Archive -Path (Join-Path $nexusStage "*") `
    -DestinationPath $nexusArchive -CompressionLevel Optimal

foreach ($archive in @($thunderstoreArchive, $nexusArchive)) {
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $line = "$hash  $([System.IO.Path]::GetFileName($archive))`n"
    [System.IO.File]::WriteAllText("$archive.sha256", $line)
    Write-Host "Created $archive"
    Write-Host "SHA-256 $hash"
}
