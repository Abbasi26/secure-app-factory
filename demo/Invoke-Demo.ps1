#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Destination
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $root 'demo-output'
}

Write-Host "Secure App Factory demo"
Write-Host "Output directory: $Destination"
Write-Host "No downloads, no install, no Intune calls."
Write-Host ""

Import-Module (Join-Path $root 'src/SecureAppFactory/SecureAppFactory.psd1') -Force
foreach ($app in @('7zip', 'notepadpp')) {
    $manifest = Join-Path $root "apps/$app/app.yaml"
    $out = Join-Path $Destination $app
    Write-Host "===== $app ====="
    Invoke-SafPipeline -ManifestPath $manifest -Destination $out -Demo -Force | Out-Null
    Get-Content -LiteralPath (Join-Path $out 'REPORT.md') -Raw | Write-Host
}

Write-Host "Demo complete. Reports: $Destination"
exit 0
