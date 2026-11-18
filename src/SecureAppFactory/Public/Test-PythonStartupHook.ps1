# Offline review of Python .pth startup hooks. Reads files only; never runs Python code.

# File names dropped by known malicious packages. Reported as Malicious whatever their content.
$script:SafKnownBadPthFile = @{
    'agent_framework_meta.pth' = 'agent-framework 1.26.1 (MAL-2026-20101)'
    'af_runtime_diag.pth'      = 'agent-framework 1.26.2 (MAL-2026-20101)'
}

# Executable lines that common tools write. A line is allowed only when both the file name and the whole line match.
$script:SafAllowedPthLine = @(
    @{ Name = '^distutils-precedence\.pth$'; Line = '^import os; var = ''SETUPTOOLS_USE_DISTUTILS''; enabled = os\.environ\.get\(var, ''local''\) == ''local''; enabled and __import__\(''_distutils_hack''\)\.add_shim\(\); ?$'; Source = 'setuptools' }
    @{ Name = '^_virtualenv\.pth$'; Line = '^import _virtualenv\s*$'; Source = 'virtualenv' }
    @{ Name = '^__editable__\.[A-Za-z0-9_.+-]+\.pth$'; Line = '^import __editable___[A-Za-z0-9_]+_finder; __editable___[A-Za-z0-9_]+_finder\.install\([^;]*\)\s*$'; Source = 'setuptools editable install' }
    @{ Name = '^pywin32\.pth$'; Line = '^import pywin32_bootstrap\s*$'; Source = 'pywin32' }
)

function Test-SafPthExecutableLine {
    # Same rule as CPython's site.addpackage: only lines that start with "import " or "import<TAB>" are executed.
    param([AllowEmptyString()][string]$Line)
    return ($Line.StartsWith('import ') -or $Line.StartsWith("import`t"))
}

function Test-PythonStartupHook {
    <#
    .SYNOPSIS
    Finds Python .pth files that run code when the interpreter starts.
    .DESCRIPTION
    Python executes every line of a .pth file in site-packages that starts with "import " on each interpreter start,
    even when no package is imported. Malicious packages use this to run without being imported, for example
    agent-framework 1.26.1 and 1.26.2 (agent_framework_meta.pth, af_runtime_diag.pth; OSV MAL-2026-20101).

    Returns one object per .pth file. Status is:
    Malicious: the file name is a known indicator of compromise.
    Suspicious: at least one executable line that is not on the allow list.
    Allowed: executable lines that exactly match a known tool (setuptools, virtualenv, editable installs, pywin32) or a name passed to -AllowFile.
    PathsOnly: no executable lines.
    The file is read as text only. Executable lines are shortened to 120 characters in the output.
    .PARAMETER Path
    site-packages folders, a source tree, or single .pth files.
    .PARAMETER Recurse
    Also look in subfolders. Python itself only reads .pth files at the top of a site directory; use -Recurse for source trees and package folders.
    .PARAMETER AllowFile
    .pth file names you have reviewed. Their executable lines are reported as Allowed. Known malicious names stay Malicious.
    .EXAMPLE
    Test-PythonStartupHook -Path (python -c "import site; print('\n'.join(site.getsitepackages()))") | Where-Object Status -ne 'PathsOnly'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string[]]$Path,
        [switch]$Recurse,
        [string[]]$AllowFile = @()
    )

    process {
        foreach ($item in $Path) {
            if (-not (Test-Path -LiteralPath $item)) {
                throw "Path not found: $item"
            }
            if (Test-Path -LiteralPath $item -PathType Leaf) {
                $files = @(Get-Item -LiteralPath $item -Force)
            }
            else {
                $files = @(Get-ChildItem -LiteralPath $item -Filter '*.pth' -File -Force -Recurse:$Recurse | Sort-Object FullName)
            }

            foreach ($file in $files) {
                if ($file.Extension -ne '.pth') { continue }
                $lines = [System.IO.File]::ReadAllLines($file.FullName, [System.Text.Encoding]::UTF8)
                $executable = @()
                $unknown = 0
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    $line = $lines[$i]
                    if ($i -eq 0) { $line = $line.TrimStart([char]0xFEFF) }
                    if (-not (Test-SafPthExecutableLine -Line $line)) { continue }

                    $source = $null
                    foreach ($rule in $script:SafAllowedPthLine) {
                        if ($file.Name -match $rule.Name -and $line -match $rule.Line) {
                            $source = $rule.Source
                            break
                        }
                    }
                    if (-not $source -and ($AllowFile -contains $file.Name)) { $source = '-AllowFile' }
                    if (-not $source) { $unknown++ }

                    $shown = $line
                    if ($shown.Length -gt 120) { $shown = $shown.Substring(0, 120) + '...' }
                    $executable += [pscustomobject]@{
                        LineNumber = $i + 1
                        Text       = $shown
                        AllowedBy  = $source
                    }
                }

                if ($script:SafKnownBadPthFile.ContainsKey($file.Name)) {
                    $status = 'Malicious'
                    $reason = 'Known malicious startup hook: ' + $script:SafKnownBadPthFile[$file.Name] + '. Do not start Python in this environment; treat its credentials as exposed.'
                }
                elseif ($unknown -gt 0) {
                    $status = 'Suspicious'
                    $reason = "$unknown executable line(s) not on the allow list. Python runs them on every start."
                }
                elseif ($executable.Count -gt 0) {
                    $status = 'Allowed'
                    $reason = 'Executable lines match: ' + ((@($executable | ForEach-Object { $_.AllowedBy }) | Select-Object -Unique) -join ', ')
                }
                else {
                    $status = 'PathsOnly'
                    $reason = 'Only path entries and comments.'
                }

                [pscustomobject]@{
                    PSTypeName      = 'SecureAppFactory.PythonStartupHook'
                    Path            = $file.FullName
                    Name            = $file.Name
                    Status          = $status
                    Reason          = $reason
                    ExecutableLines = $executable
                }
            }
        }
    }
}
