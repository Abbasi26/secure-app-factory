# Secure App Factory 0.2.0
# Local packaging pipeline. No telemetry. Network calls happen only when a caller asks for them.

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:SafVersion = '0.2.0'
$script:SafRoot = $PSScriptRoot

Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' | ForEach-Object {
    . $_.FullName
}
Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' | ForEach-Object {
    . $_.FullName
}
