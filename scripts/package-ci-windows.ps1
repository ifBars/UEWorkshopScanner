[CmdletBinding()]
param(
    [string] $OutputDirectory = (Join-Path $PSScriptRoot "..\artifacts\ci")
)

$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$stageRoot = Join-Path $outputRoot "UEWorkshopScanner-experimental-windows-x64"

Push-Location $projectRoot
try {
    cargo build --locked --release
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
New-Item -ItemType Directory -Path $stageRoot | Out-Null

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

Write-Host "Prepared decoder-free CI artifact at $stageRoot"
