[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $OodlePath,

    [string] $Version = "0.1.0",

    [string] $OutputDirectory = (Join-Path $PSScriptRoot "..\artifacts\release")
)

$ErrorActionPreference = "Stop"
$approvedOodleSha256 = @(
    "6f5d41a7892ea6b2db420f2458dad2f84a63901c9a93ce9497337b16c195f457",
    "111a505e64a3bf1b89c05aab2dd16306bc2267a5ea3f0c9722a3b6152091ce1c"
)
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$rustRoot = $projectRoot
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$archiveName = "UEWorkshopScanner-$Version-windows-x64"
$stageRoot = Join-Path $outputRoot $archiveName
$archivePath = Join-Path $outputRoot "$archiveName.zip"

$actualOodleSha256 = (Get-FileHash -LiteralPath $OodlePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualOodleSha256 -notin $approvedOodleSha256) {
    throw "Oodle digest mismatch. The supplied DLL is not an approved Epic Oodle 2.9.10 redistributable; got $actualOodleSha256."
}

Push-Location $rustRoot
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
if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
}
New-Item -ItemType Directory -Path $stageRoot | Out-Null

Copy-Item -LiteralPath (Join-Path $rustRoot "target\release\ue-workshop-scanner.exe") -Destination $stageRoot
Copy-Item -LiteralPath $OodlePath -Destination (Join-Path $stageRoot "oo2core_9_win64.dll")
Copy-Item -LiteralPath (Join-Path $projectRoot "BINARY-EULA.txt") -Destination $stageRoot
Copy-Item -LiteralPath (Join-Path $projectRoot "THIRD_PARTY_NOTICES.txt") -Destination $stageRoot
Copy-Item -LiteralPath (Join-Path $projectRoot "LICENSE") -Destination $stageRoot
Copy-Item -LiteralPath (Join-Path $projectRoot "README.md") -Destination $stageRoot

$hashLines = Get-ChildItem -LiteralPath $stageRoot -File |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    }
[System.IO.File]::WriteAllLines((Join-Path $stageRoot "SHA256SUMS"), $hashLines)

Compress-Archive -LiteralPath $stageRoot -DestinationPath $archivePath -CompressionLevel Optimal
$archiveSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText("$archivePath.sha256", "$archiveSha256  $([System.IO.Path]::GetFileName($archivePath))`n")

Write-Host "Created $archivePath"
Write-Host "SHA-256 $archiveSha256"
