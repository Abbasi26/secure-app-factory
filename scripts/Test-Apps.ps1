#Requires -Version 7.0
# Offline check of every apps/<id> folder. Exit 1 on an error, or on a warning with -FailOnWarning.
[CmdletBinding()]
param(
    [string]$Path,
    [string]$SummaryPath,
    [string]$JsonPath,
    [switch]$FailOnWarning
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Path) { $Path = Join-Path $root 'apps' }
Import-Module (Join-Path $root 'src/SecureAppFactory/SecureAppFactory.psd1') -Force

$apps = @(Get-ChildItem -LiteralPath $Path -Directory | ForEach-Object Name)
$findings = @(Test-SafAppCatalog -Path $Path)
if ($findings.Count -gt 0) {
    $findings | Format-Table -AutoSize -Wrap App, Severity, Check, Message | Out-String -Width 200 | Write-Host
}
if ($JsonPath) {
    $jsonDir = Split-Path -Parent $JsonPath
    if ($jsonDir -and -not (Test-Path -LiteralPath $jsonDir -PathType Container)) {
        New-Item -ItemType Directory -Path $jsonDir -Force | Out-Null
    }
    $findings | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $JsonPath -NoNewline
}
$markdown = $findings | ConvertTo-SafCatalogMarkdown -Apps $apps
if ($SummaryPath) {
    Add-Content -LiteralPath $SummaryPath -Value $markdown
}
$errors = @($findings | Where-Object Severity -eq 'Error').Count
$warnings = @($findings | Where-Object Severity -eq 'Warning').Count
Write-Host ("{0} apps checked: {1} errors, {2} warnings." -f $apps.Count, $errors, $warnings)
if ($errors -gt 0 -or ($FailOnWarning -and $warnings -gt 0)) { exit 1 }
exit 0