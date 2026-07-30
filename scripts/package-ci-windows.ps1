[CmdletBinding()]
param(
    [string] $OutputDirectory = (Join-Path $PSScriptRoot "..\artifacts\ci")
)

$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$stageRoot = Join-Path $outputRoot "UEWorkshopScanner-experimental-windows-x64"
$guiStageRoot = Join-Path $outputRoot "UEWorkshopScanner-desktop-experimental-windows-x64"

Push-Location $projectRoot
try {
    cargo build --locked --release --workspace
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
if (Test-Path -LiteralPath $stageRoot) {
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
if (Test-Path -LiteralPath $guiStageRoot) {
    Remove-Item -LiteralPath $guiStageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $stageRoot | Out-Null
New-Item -ItemType Directory -Path $guiStageRoot | Out-Null

foreach ($file in @(
    "EXPERIMENTAL.txt",
    "LICENSE",
    "OODLE-SETUP.txt",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.txt"
)) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $file) -Destination $stageRoot
}
Copy-Item -LiteralPath (Join-Path $projectRoot "target\release\ue-workshop-scanner.exe") `
    -Destination $stageRoot

$hashLines = Get-ChildItem -LiteralPath $stageRoot -File |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    }
[System.IO.File]::WriteAllLines((Join-Path $stageRoot "SHA256SUMS"), $hashLines)

foreach ($file in @(
    "EXPERIMENTAL.txt",
    "LICENSE",
    "OODLE-SETUP.txt",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.txt"
)) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $file) -Destination $guiStageRoot
}
Copy-Item -LiteralPath (Join-Path $projectRoot "gui\README-FIRST.txt") -Destination $guiStageRoot
Copy-Item -LiteralPath (Join-Path $projectRoot "target\release\ue-workshop-scanner-gui.exe") `
    -Destination (Join-Path $guiStageRoot "UEWorkshopScanner.exe")

$guiHashLines = Get-ChildItem -LiteralPath $guiStageRoot -File |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    }
[System.IO.File]::WriteAllLines((Join-Path $guiStageRoot "SHA256SUMS"), $guiHashLines)

Write-Host "Prepared decoder-free CI artifact at $stageRoot"
Write-Host "Prepared decoder-free desktop artifact at $guiStageRoot"
