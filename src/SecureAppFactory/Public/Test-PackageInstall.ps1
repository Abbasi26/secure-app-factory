function Get-SafSuccessCodes {
    param($Manifest)

    $codes = New-Object System.Collections.Generic.List[int]
    foreach ($field in @('successExitCodes', 'rebootExitCodes')) {
        $values = Get-SafProp -Object $Manifest -Name @('psadt', $field)
        if ($null -eq $values) { continue }
        foreach ($value in @($values)) {
            $codes.Add([int]$value)
        }
    }
    if ($codes.Count -eq 0) {
        $codes.Add(0)
        $codes.Add(3010)
        $codes.Add(1641)
    }
    return $codes.ToArray()
}

function ConvertTo-SafRegistryMachinePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $expanded = Expand-SafMachinePath -Path $Path
    if ($expanded -match '^[A-Za-z]+:\\') { return $expanded }
    $map = @{
        'HKEY_LOCAL_MACHINE' = 'HKLM:'
        'HKEY_CURRENT_USER'  = 'HKCU:'
        'HKEY_CLASSES_ROOT'  = 'HKCR:'
        'HKEY_USERS'         = 'HKU:'
    }
    foreach ($key in $map.Keys) {
        if ($expanded.StartsWith($key)) {
            return $map[$key] + $expanded.Substring($key.Length)
        }
    }
    return $expanded
}

function ConvertTo-SafRegistryIntunePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $expanded = Expand-SafIntunePath -Path $Path
    $map = @{
        'HKLM:' = 'HKEY_LOCAL_MACHINE'
        'HKCU:' = 'HKEY_CURRENT_USER'
        'HKCR:' = 'HKEY_CLASSES_ROOT'
        'HKU:'  = 'HKEY_USERS'
    }
    foreach ($key in $map.Keys) {
        if ($expanded.StartsWith($key)) {
            return $map[$key] + $expanded.Substring($key.Length)
        }
    }
    return $expanded
}

function Test-SafDetection {
    param(
        [Parameter(Mandatory = $true)]
        $Manifest
    )

    $type = [string]$Manifest.detection.type
    $path = Expand-SafMachinePath -Path ([string]$Manifest.detection.path)
    if ($type -eq 'file') {
        return [bool](Test-Path -LiteralPath $path -PathType Leaf)
    }
    if (-not (Get-SafIsWindows)) {
        throw 'Registry detection runs on Windows only.'
    }
    $machinePath = ConvertTo-SafRegistryMachinePath -Path $path
    $valueName = [string]$Manifest.detection.name
    $item = $null
    try {
        $item = Get-ItemProperty -LiteralPath $machinePath -Name $valueName -ErrorAction Stop
    }
    catch {
        return $false
    }
    $expected = Get-SafProp -Object $Manifest -Name @('detection', 'value')
    if ($null -eq $expected -or [string]$expected -eq '') {
        return $true
    }
    return ([string]($item.$valueName) -eq [string]$expected)
}

function Get-SafDetectionText {
    param($Manifest)
    $type = [string]$Manifest.detection.type
    $path = [string]$Manifest.detection.path
    if ($type -eq 'file') {
        return "file $path"
    }
    $name = [string]$Manifest.detection.name
    $value = [string](Get-SafProp -Object $Manifest -Name @('detection', 'value'))
    if ([string]::IsNullOrWhiteSpace($value)) {
        return "registry $path name $name exists"
    }
    return "registry $path name $name equals $value"
}

function Invoke-SafCheckedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [AllowEmptyString()][string]$Arguments,
        [ValidateRange(1, 2147483)][int]$TimeoutSeconds
    )

    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "Executable not found: $FilePath"
    }
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $FilePath
    $start.Arguments = $Arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($start)
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }
        throw "Process timed out after $TimeoutSeconds seconds: $FilePath"
    }
    return [int]$process.ExitCode
}

function Wait-SafDetectionState {
    param(
        $Manifest,
        [bool]$Expected,
        [int]$Retries,
        [int]$DelaySeconds
    )

    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        $found = [bool](Test-SafDetection -Manifest $Manifest)
        if ($found -eq $Expected) { return $true }
        if ($DelaySeconds -gt 0 -and $attempt -lt $Retries) {
            Start-Sleep -Seconds $DelaySeconds
        }
    }
    return $false
}

function Test-PackageInstall {
    <#
    .SYNOPSIS
        Previews or runs the silent install, detection, and uninstall smoke test.

    .DESCRIPTION
        Without -SmokeTest this command does not start the installer. It returns the commands it would run.
        -SmokeTest runs on Windows only. Command mode runs the vendor installer. Toolkit mode runs the generated PSADT script.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Manifest,
        [Parameter(Mandatory = $true)]
        [string]$InstallerPath,
        [ValidateSet('Command', 'Toolkit')]
        [string]$Mode = 'Command',
        [string]$PackageRoot,
        [switch]$SmokeTest,
        [ValidateRange(1, 2147483)][int]$TimeoutSeconds = 600,
        [int]$DetectionRetries = 10,
        [int]$DetectionDelaySeconds = 2
    )

    $installArguments = [string]$Manifest.install.arguments
    $uninstallPath = Expand-SafMachinePath -Path ([string]$Manifest.uninstall.filePath)
    $uninstallArguments = [string]$Manifest.uninstall.arguments
    $detection = Get-SafDetectionText -Manifest $Manifest
    $installCommand = '"{0}" {1}' -f $InstallerPath, $installArguments
    $uninstallCommand = '"{0}" {1}' -f $uninstallPath, $uninstallArguments
    if ($Mode -eq 'Toolkit') {
        $scriptPath = Join-Path $PackageRoot 'Invoke-AppDeployToolkit.ps1'
        $installCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -DeploymentType Install -DeployMode Silent"
        $uninstallCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -DeploymentType Uninstall -DeployMode Silent"
    }

    if (-not $SmokeTest) {
        return [pscustomobject]@{
            Status             = 'Preview'
            Passed             = $true
            Executed           = $false
            Mode               = $Mode
            InstallCommand     = $installCommand.Trim()
            UninstallCommand   = $uninstallCommand.Trim()
            Detection          = $detection
            InstallExitCode    = $null
            UninstallExitCode  = $null
            Reason             = 'Smoke test was not requested. Nothing was installed.'
        }
    }
    if (-not (Get-SafIsWindows)) {
        throw 'The smoke test installs software and runs on Windows only.'
    }

    $allowed = @(Get-SafSuccessCodes -Manifest $Manifest)
    if ($Mode -eq 'Command') {
        $installExit = Invoke-SafCheckedProcess -FilePath $InstallerPath -Arguments $installArguments -TimeoutSeconds $TimeoutSeconds
    }
    else {
        if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
            throw 'Toolkit smoke test requires -PackageRoot.'
        }
        $scriptPath = Join-Path $PackageRoot 'Invoke-AppDeployToolkit.ps1'
        $shell = 'powershell.exe'
        if (-not (Get-Command -Name $shell -ErrorAction SilentlyContinue)) {
            $shell = 'pwsh'
        }
        $installExit = Invoke-SafCheckedProcess -FilePath $shell -Arguments ("-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -DeploymentType Install -DeployMode Silent") -TimeoutSeconds $TimeoutSeconds
    }
    if ($allowed -notcontains $installExit) {
        throw "Install exit code $installExit is not in the success list ($($allowed -join ', '))."
    }
    if (-not (Wait-SafDetectionState -Manifest $Manifest -Expected $true -Retries $DetectionRetries -DelaySeconds $DetectionDelaySeconds)) {
        throw "Detection did not succeed after install: $detection"
    }

    if ($Mode -eq 'Command') {
        $uninstallExit = Invoke-SafCheckedProcess -FilePath $uninstallPath -Arguments $uninstallArguments -TimeoutSeconds $TimeoutSeconds
    }
    else {
        $scriptPath = Join-Path $PackageRoot 'Invoke-AppDeployToolkit.ps1'
        $shell = 'powershell.exe'
        if (-not (Get-Command -Name $shell -ErrorAction SilentlyContinue)) {
            $shell = 'pwsh'
        }
        $uninstallExit = Invoke-SafCheckedProcess -FilePath $shell -Arguments ("-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -DeploymentType Uninstall -DeployMode Silent") -TimeoutSeconds $TimeoutSeconds
    }
    if ($allowed -notcontains $uninstallExit) {
        throw "Uninstall exit code $uninstallExit is not in the success list ($($allowed -join ', '))."
    }
    if (-not (Wait-SafDetectionState -Manifest $Manifest -Expected $false -Retries $DetectionRetries -DelaySeconds $DetectionDelaySeconds)) {
        throw "Detection still matches after uninstall: $detection"
    }

    return [pscustomobject]@{
        Status            = 'Passed'
        Passed            = $true
        Executed          = $true
        Mode              = $Mode
        InstallCommand    = $installCommand.Trim()
        UninstallCommand  = $uninstallCommand.Trim()
        Detection         = $detection
        InstallExitCode   = $installExit
        UninstallExitCode = $uninstallExit
        Reason            = 'Silent install, detection, and uninstall completed.'
    }
}

