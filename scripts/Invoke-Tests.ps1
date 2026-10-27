#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$pester = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -ge [version]'5.0.0' } | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) {
    throw 'Pester 5 is required. Install it with: Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser'
}
Import-Module Pester -RequiredVersion $pester.Version -Force
$config = New-PesterConfiguration
$config.Run.Path = Join-Path $root 'tests'
$config.Run.Exit = $true
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config
