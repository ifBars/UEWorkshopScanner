param(
    [switch] $Check
)

$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$outputPath = Join-Path $projectRoot "THIRD_PARTY_LICENSES.txt"
$temporaryPath = Join-Path ([System.IO.Path]::GetTempPath()) `
    "ue-workshop-scanner-third-party-licenses-$PID.txt"

try {
    & cargo about --version *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "cargo-about is required. Install it with: cargo install --locked --features cli cargo-about"
    }

    & cargo about generate `
        --locked `
        --fail `
        --output-file $temporaryPath `
        (Join-Path $projectRoot "about.hbs")
    if ($LASTEXITCODE -ne 0) {
        throw "cargo-about failed with exit code $LASTEXITCODE."
    }
    $generated = [System.IO.File]::ReadAllText($temporaryPath).TrimEnd() + "`n"
    [System.IO.File]::WriteAllText($temporaryPath, $generated)

    if ($Check) {
        if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
            throw "THIRD_PARTY_LICENSES.txt is missing. Run this script without -Check."
        }
        $expected = [System.IO.File]::ReadAllText($outputPath)
        $actual = [System.IO.File]::ReadAllText($temporaryPath)
        if ($expected -ne $actual) {
            throw "THIRD_PARTY_LICENSES.txt is stale. Run this script without -Check."
        }
        Write-Host "THIRD_PARTY_LICENSES.txt matches Cargo.lock."
    } else {
        Copy-Item -LiteralPath $temporaryPath -Destination $outputPath -Force
        Write-Host "Updated $outputPath"
    }
} finally {
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}
