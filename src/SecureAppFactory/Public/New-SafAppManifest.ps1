# Writes apps/<id>/app.yaml and lock.json for a reviewed installer. No download; the hash comes from
# -Sha256 or from a local file you already fetched and reviewed.

function ConvertTo-SafYamlQuoted {
    param([AllowEmptyString()][string]$Value)
    return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}

function New-SafAppManifest {
    <#
    .SYNOPSIS
    Creates apps/<id>/app.yaml and lock.json from parameters, validated against the manifest schema.
    .DESCRIPTION
    Does not download or run anything. Pass -Sha256 with the digest the vendor publishes, or
    -InstallerPath with a local copy you already reviewed; the function hashes that file.
    Refuses to overwrite an existing app folder unless -Force is set. Supports -WhatIf.
    .EXAMPLE
    New-SafAppManifest -Id putty -Name PuTTY -Version 0.83 -Publisher "Simon Tatham" `
      -Url https://the.earth.li/~sgtatham/putty/0.83/w64/putty-64bit-0.83-installer.msi `
      -InstallerPath ./putty-64bit-0.83-installer.msi -InstallArguments "/qn" `
      -UninstallPath "{SystemRoot}\System32\msiexec.exe" -UninstallArguments "/x {PRODUCT-CODE} /qn" `
      -DetectionPath "{ProgramFiles}\PuTTY\putty.exe"
    #>
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Hash')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-z0-9-]+$')]
        [string]$Id,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$Publisher,
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true, ParameterSetName = 'Hash')]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$Sha256,
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]$InstallerPath,
        [ValidateSet('x86', 'x64', 'arm64')]
        [string]$Architecture = 'x64',
        [string]$FileName,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$InstallArguments,
        [Parameter(Mandatory = $true)][string]$UninstallPath,
        [AllowEmptyString()]
        [string]$UninstallArguments = '',
        [ValidateSet('file', 'registry')]
        [string]$DetectionType = 'file',
        [Parameter(Mandatory = $true)][string]$DetectionPath,
        [string]$DetectionName,
        [string]$SignatureSubject,
        [ValidatePattern('^[A-Fa-f0-9]{40}$')]
        [string]$SignatureThumbprint,
        [string]$License,
        [string]$Description,
        [string]$AppsPath = 'apps',
        [switch]$Force
    )

    # ValidatePattern is case-insensitive; folder ids must be lowercase.
    if ($Id -cnotmatch '^[a-z0-9-]+$') {
        throw "-Id must be lowercase letters, digits, and hyphens: '$Id'."
    }
    if (-not (Test-SafHttpsUrl $Url)) {
        throw 'Url must be an https URL without embedded credentials.'
    }
    if ($SignatureThumbprint -and -not $SignatureSubject) {
        throw '-SignatureThumbprint requires -SignatureSubject.'
    }
    if ($DetectionType -eq 'registry' -and -not $DetectionName) {
        throw 'A registry detection rule needs -DetectionName.'
    }

    if ($PSCmdlet.ParameterSetName -eq 'File') {
        if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
            throw "Installer not found: $InstallerPath"
        }
        $Sha256 = Get-SafSha256 -Path $InstallerPath
    }
    $Sha256 = $Sha256.ToLowerInvariant()

    if (-not $FileName) {
        $FileName = [System.Uri]::UnescapeDataString(([System.Uri]$Url).Segments[-1])
    }
    if ($FileName -notmatch '^[A-Za-z0-9._+-]+$') {
        throw "Cannot use '$FileName' as source.fileName. Pass -FileName with letters, digits, dot, underscore, plus, or hyphen."
    }

    $q = { param($v) ConvertTo-SafYamlQuoted $v }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# $Name $Version $Architecture. Created with New-SafAppManifest.")
    $lines.Add('# Review install, uninstall, and detection on a test machine before the first upload.')
    $lines.Add('name: ' + (& $q $Name))
    $lines.Add('version: ' + (& $q $Version))
    $lines.Add('publisher: ' + (& $q $Publisher))
    $lines.Add("architecture: $Architecture")
    if ($Description) { $lines.Add('description: ' + (& $q $Description)) }
    if ($License) {
        if ($License -notmatch '^[A-Za-z0-9.+-]+$') { throw '-License must be an SPDX-style token, for example MIT or GPL-3.0-only.' }
        $lines.Add("license: $License")
    }
    $lines.Add('')
    $lines.Add('source:')
    $lines.Add('  type: url')
    $lines.Add('  url: ' + (& $q $Url))
    $lines.Add("  fileName: $FileName")
    $lines.Add('')
    $lines.Add('trust:')
    $lines.Add('  algorithm: SHA256')
    $lines.Add("  value: $Sha256")
    $lines.Add('  signature:')
    if ($SignatureSubject) {
        $lines.Add('    required: true')
        $lines.Add('    subjectContains: ' + (& $q $SignatureSubject))
        if ($SignatureThumbprint) { $lines.Add('    thumbprint: ' + $SignatureThumbprint.ToUpperInvariant()) }
    }
    else {
        $lines.Add('    required: false')
    }
    $lines.Add('')
    $lines.Add('install:')
    $lines.Add('  arguments: ' + (& $q $InstallArguments))
    $lines.Add('')
    $lines.Add('uninstall:')
    $lines.Add('  filePath: ' + (& $q $UninstallPath))
    $lines.Add('  arguments: ' + (& $q $UninstallArguments))
    $lines.Add('')
    $lines.Add('detection:')
    $lines.Add("  type: $DetectionType")
    $lines.Add('  path: ' + (& $q $DetectionPath))
    if ($DetectionType -eq 'registry') { $lines.Add('  name: ' + (& $q $DetectionName)) }
    $yaml = ($lines -join "`n") + "`n"

    $parsed = ConvertTo-SafData -Node (ConvertFrom-SafYaml -Yaml $yaml)
    $schemaErrors = Test-SafManifestSchema -Manifest $parsed
    $schemaErrors = @($schemaErrors | Where-Object { $_ })
    if ($schemaErrors.Count -gt 0) {
        throw ("The generated manifest does not pass the schema:`n - {0}" -f ($schemaErrors -join "`n - "))
    }

    $appDir = Join-Path $AppsPath $Id
    $manifestPath = Join-Path $appDir 'app.yaml'
    $lockPath = Join-Path $appDir 'lock.json'
    if ((Test-Path -LiteralPath $manifestPath) -or (Test-Path -LiteralPath $lockPath)) {
        if (-not $Force) {
            throw "App '$Id' already exists under $AppsPath. Pass -Force to replace app.yaml and lock.json."
        }
    }

    $lock = [ordered]@{
        algorithm  = 'SHA256'
        value      = $Sha256
        source     = $Url
        recordedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        recordedBy = 'new-safappmanifest'
    }

    if ($PSCmdlet.ShouldProcess($appDir, 'Write app.yaml and lock.json')) {
        Write-SafTextFile -Path $manifestPath -Text $yaml
        Write-SafJsonFile -Path $lockPath -Value $lock
    }

    [pscustomobject]@{
        Id           = $Id
        ManifestPath = $manifestPath
        LockPath     = $lockPath
        Sha256       = $Sha256
        Yaml         = $yaml
    }
}
