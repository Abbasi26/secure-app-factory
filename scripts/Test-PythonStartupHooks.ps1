#Requires -Version 5.1
# Lists Python .pth startup hooks and exits 1 when one is Malicious or Suspicious. Reads files only.
# Without -Path it asks the first python3/python on PATH for its site-packages folders.
[CmdletBinding()]
param(
    [string[]]$Path,
    [switch]$Recurse,
    [string[]]$AllowFile = @(),
    [string]$SummaryPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src/SecureAppFactory/SecureAppFactory.psd1') -Force

if (-not $Path) {
    $python = Get-Command -Name python3, python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $python) {
        Write-Host 'No python3 or python on PATH and no -Path given. Nothing to check.'
        exit 0
    }
    $code = 'import site, sys; d = list(site.getsitepackages()) + [site.getusersitepackages()]; print("\n".join(d))'
    $Path = @(& $python.Source -I -S -c $code | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) })
    Write-Host ("Python: {0}" -f $python.Source)
}

$results = @(foreach ($item in $Path) { Test-PythonStartupHook -Path $item -Recurse:$Recurse -AllowFile $AllowFile })
if ($results.Count -gt 0) {
    $results | Format-Table -AutoSize -Wrap Status, Name, Reason, Path | Out-String -Width 200 | Write-Host
}
$bad = @($results | Where-Object { $_.Status -eq 'Malicious' -or $_.Status -eq 'Suspicious' })
foreach ($hit in $bad) {
    foreach ($line in $hit.ExecutableLines | Where-Object { -not $_.AllowedBy }) {
        Write-Host ("  {0}:{1}: {2}" -f $hit.Name, $line.LineNumber, $line.Text)
    }
}
if ($SummaryPath) {
    $md = @('## Python startup hooks', '', '| Status | File | Reason |', '| --- | --- | --- |')
    foreach ($r in $results) { $md += ('| {0} | `{1}` | {2} |' -f $r.Status, $r.Name, $r.Reason) }
    if ($results.Count -eq 0) { $md += '| - | no .pth files | - |' }
    Add-Content -LiteralPath $SummaryPath -Value ($md -join "`n")
}
Write-Host ("{0} .pth files checked in {1} folder(s): {2} malicious or suspicious." -f $results.Count, @($Path).Count, $bad.Count)
if ($bad.Count -gt 0) { exit 1 }
exit 0
