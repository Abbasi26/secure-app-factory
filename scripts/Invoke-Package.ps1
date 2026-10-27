#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9-]+$')]
    [string]$App,
    [Parameter(Mandatory = $true)]
    [string]$Destination,
    [switch]$SmokeTest,
    [ValidateSet('Command', 'Toolkit')]
    [string]$SmokeTestMode = 'Command',
    [switch]$IncludeToolkit,
    [switch]$DownloadContentPrepTool,
    [switch]$Upload,
    [switch]$Demo,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src/SecureAppFactory/SecureAppFactory.psd1') -Force
$manifest = Join-Path $root "apps/$App/app.yaml"
if (-not (Test-Path -LiteralPath $manifest)) {
    throw "Unknown app '$App'. Expected $manifest"
}

$params = @{
    ManifestPath = $manifest
    Destination  = $Destination
}
if ($SmokeTest) { $params.SmokeTest = $true }
if ($SmokeTestMode) { $params.SmokeTestMode = $SmokeTestMode }
if ($IncludeToolkit) { $params.IncludeToolkit = $true }
if ($DownloadContentPrepTool) { $params.DownloadContentPrepTool = $true }
if ($Upload) { $params.Upload = $true }
if ($Demo) { $params.Demo = $true }
if ($Force) { $params.Force = $true }

$result = Invoke-SafPipeline @params
Write-Host "Report: $($result.ReportPath)"
if ($Upload -and $result.Upload.Status -eq 'Skipped') {
    throw 'Intune upload was requested but the SAF_INTUNE_* secrets are not all set.'
}
exit 0
