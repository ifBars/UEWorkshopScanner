[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$packageRoot = Join-Path $projectRoot "integrations\meccha-ue4ss\package"
$manifestPath = Join-Path $packageRoot "manifest.json"
$iconPath = Join-Path $packageRoot "icon.png"
$scriptPath = Join-Path $packageRoot "UEWorkshopScanner\Scripts\main.lua"
$enabledPath = Join-Path $packageRoot "UEWorkshopScanner\enabled.txt"
$committedBin = Join-Path $packageRoot "UEWorkshopScanner\bin"

if (Test-Path -LiteralPath $committedBin) {
    throw "Compiled scanner or Oodle files must not be committed under the package template."
}

foreach ($required in @(
    $manifestPath,
    $iconPath,
    (Join-Path $packageRoot "README.md"),
    $scriptPath,
    $enabledPath
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required package file is missing: $required"
    }
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.name -ne "UEWorkshopScanner") {
    throw "Unexpected Thunderstore package name: $($manifest.name)"
}
if ($manifest.version_number -notmatch '^\d+\.\d+\.\d+$') {
    throw "Thunderstore version must use X.Y.Z format: $($manifest.version_number)"
}
if ($manifest.dependencies -notcontains "Thunderstore-MecchaChameleon_UE4SS-1.0.0") {
    throw "The current Meccha UE4SS overlay dependency is missing."
}

$png = [System.IO.File]::ReadAllBytes($iconPath)
$signature = [byte[]](137, 80, 78, 71, 13, 10, 26, 10)
$validSignature = $png.Length -ge 24
for ($index = 0; $validSignature -and $index -lt $signature.Length; $index++) {
    $validSignature = $png[$index] -eq $signature[$index]
}
if (-not $validSignature) {
    throw "Thunderstore icon is not a PNG."
}
$width = ([uint32]$png[16] -shl 24) -bor
    ([uint32]$png[17] -shl 16) -bor
    ([uint32]$png[18] -shl 8) -bor
    [uint32]$png[19]
$height = ([uint32]$png[20] -shl 24) -bor
    ([uint32]$png[21] -shl 16) -bor
    ([uint32]$png[22] -shl 8) -bor
    [uint32]$png[23]
if ($width -ne 256 -or $height -ne 256) {
    throw "Thunderstore icon must be exactly 256x256; got ${width}x${height}."
}

$lua = Get-Content -LiteralPath $scriptPath -Raw
foreach ($contract in @(
    "RegisterKeyBind",
    "ExecuteAsync",
    "--game meccha-chameleon",
    "ForEachUObject",
    "observe-only"
)) {
    if (-not $lua.Contains($contract)) {
        throw "UE4SS prototype is missing expected contract text: $contract"
    }
}

Write-Host "Meccha UE4SS package source is valid."
