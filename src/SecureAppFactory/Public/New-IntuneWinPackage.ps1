function Resolve-SafContentPrepTool {
    param(
        [string]$ToolPath,
        [switch]$DownloadTool,
        [string]$ToolCache,
        [scriptblock]$WebClient
    )

    $tools = Get-SafExternalTools
    $expected = ([string]$tools.intuneWinAppUtil.exeSha256).ToLowerInvariant()
    if (-not $ToolCache) {
        $ToolCache = Join-Path ([System.IO.Path]::GetTempPath()) 'secure-app-factory'
    }

    if ($DownloadTool) {
        if (-not (Get-SafIsWindows)) {
            throw 'IntuneWinAppUtil.exe runs on Windows only. -DownloadTool was not executed.'
        }
        $archive = Join-Path $ToolCache 'Microsoft-Win32-Content-Prep-Tool-1.8.7.zip'
        Invoke-SafDownloadFile -Uri ([string]$tools.intuneWinAppUtil.archiveUrl) -Destination $archive -WebClient $WebClient
        $extract = Join-Path $ToolCache 'intunewin-tool'
        if (Test-Path -LiteralPath $extract) {
            Remove-Item -LiteralPath $extract -Recurse -Force
        }
        Expand-SafZip -ZipPath $archive -Destination $extract
        $exe = Get-ChildItem -LiteralPath $extract -Recurse -Filter 'IntuneWinAppUtil.exe' | Select-Object -First 1
        if (-not $exe) {
            throw 'The content prep tool archive did not contain IntuneWinAppUtil.exe.'
        }
        $ToolPath = $exe.FullName
    }

    if ([string]::IsNullOrWhiteSpace($ToolPath)) {
        return $null
    }
    if (-not (Test-Path -LiteralPath $ToolPath)) {
        throw "IntuneWinAppUtil.exe was not found: $ToolPath"
    }
    $observed = Get-SafSha256 -Path $ToolPath
    if ($observed -ne $expected) {
        throw "IntuneWinAppUtil.exe hash mismatch. Expected the pinned 1.8.7 build $expected. Observed $observed. This repository does not redistribute the tool."
    }
    return $ToolPath
}

function New-IntuneWinPackage {
    <#
    .SYNOPSIS
        Creates an .intunewin with Microsoft's Win32 Content Prep Tool when that tool is available.

    .DESCRIPTION
        The executable is not part of this repository. Its license is Microsoft's, not MIT.
        Passing -DownloadTool downloads the pinned 1.8.7 archive from the official GitHub tag and checks the executable hash.
        Passing that switch means the operator has reviewed and accepts Microsoft's license terms.
        Without -DownloadTool and without -ToolPath, this command creates nothing and returns Status Skipped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceFolder,
        [Parameter(Mandatory = $true)]
        [string]$SetupFile,
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [string]$ToolPath,
        [switch]$DownloadTool,
        [string]$ToolCache,
        [scriptblock]$WebClient
    )

    if (-not $DownloadTool -and [string]::IsNullOrWhiteSpace($ToolPath)) {
        return [pscustomobject]@{
            Status = 'Skipped'
            Path   = ''
            Reason = 'IntuneWinAppUtil was not requested. No .intunewin file was created.'
        }
    }
    if (-not (Get-SafIsWindows)) {
        throw 'IntuneWinAppUtil.exe runs on Windows only. No .intunewin file was created.'
    }

    $resolved = Resolve-SafContentPrepTool -ToolPath $ToolPath -DownloadTool:$DownloadTool -ToolCache $ToolCache -WebClient $WebClient
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        throw 'IntuneWinAppUtil.exe could not be resolved.'
    }
    if (-not (Test-Path -LiteralPath $SourceFolder)) {
        throw "Source folder not found: $SourceFolder"
    }
    $setupFull = $SetupFile
    if (-not [System.IO.Path]::IsPathRooted($setupFull)) {
        $setupFull = Join-Path $SourceFolder $SetupFile
    }
    if (-not (Test-Path -LiteralPath $setupFull)) {
        throw "Setup file not found: $setupFull"
    }
    foreach ($pathValue in @($SourceFolder, $setupFull, $Destination)) {
        if ($pathValue.Contains('"')) {
            throw "Paths passed to IntuneWinAppUtil cannot contain quotes: $pathValue"
        }
    }
    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    $argumentString = '-c "{0}" -s "{1}" -o "{2}" -q' -f $SourceFolder, $setupFull, $Destination
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $resolved
    $start.Arguments = $argumentString
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($start)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -ne 0) {
        throw "IntuneWinAppUtil.exe exited with code $($process.ExitCode). $stdout $stderr"
    }

    $created = Get-ChildItem -LiteralPath $Destination -Filter '*.intunewin' | Select-Object -First 1
    if (-not $created) {
        throw "IntuneWinAppUtil.exe exited 0 but no .intunewin file was written to $Destination. $stdout $stderr"
    }
    return [pscustomobject]@{
        Status     = 'Created'
        Path       = $created.FullName
        Reason     = 'Created with the pinned Microsoft Win32 Content Prep Tool 1.8.7.'
        ToolPath   = $resolved
        ExitCode   = $process.ExitCode
    }
}
