# Offline review of every apps/<id> folder. Reads files only; no download, no network.

function New-SafCatalogFinding {
    param([string]$App, [string]$Severity, [string]$Check, [string]$Message)
    [pscustomobject]@{
        PSTypeName = 'SecureAppFactory.CatalogFinding'
        App        = $App
        Severity   = $Severity
        Check      = $Check
        Message    = $Message
    }
}

function Test-SafAppCatalog {
    <#
    .SYNOPSIS
    Checks every apps/<id>/app.yaml and lock.json without downloading anything.
    .DESCRIPTION
    Returns one finding per problem. Severity is Error, Warning, or Info.
    Error: the build would fail or the pin is missing or inconsistent.
    Warning: the build passes but a reviewer should look (no thumbprint, a URL that does not name the version, a lock file recorded for a different URL).
    Info: a note about the trust model (hash pin only, Evergreen source).
    .EXAMPLE
    Test-SafAppCatalog -Path ./apps | Format-Table
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Path = 'apps'
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Apps directory not found: $Path"
    }

    $dirs = @(Get-ChildItem -LiteralPath $Path -Directory | Sort-Object Name)
    if ($dirs.Count -eq 0) {
        New-SafCatalogFinding -App '' -Severity 'Warning' -Check 'catalog' -Message "No app folders under $Path."
        return
    }

    $seenUrls = @{}
    foreach ($dir in $dirs) {
        $id = $dir.Name
        if ($id -cnotmatch '^[a-z0-9-]+$') {
            New-SafCatalogFinding -App $id -Severity 'Error' -Check 'id' -Message "Folder name must match ^[a-z0-9-]+$ so scripts/Invoke-Package.ps1 -App can select it."
        }

        $manifestPath = Join-Path $dir.FullName 'app.yaml'
        if (-not (Test-Path -LiteralPath $manifestPath)) {
            New-SafCatalogFinding -App $id -Severity 'Error' -Check 'manifest' -Message 'app.yaml is missing.'
            continue
        }

        try {
            $manifest = ConvertTo-SafData -Node (ConvertFrom-SafYaml -Yaml ([System.IO.File]::ReadAllText($manifestPath)))
        }
        catch {
            New-SafCatalogFinding -App $id -Severity 'Error' -Check 'yaml' -Message ("app.yaml does not parse: {0}" -f $_.Exception.Message)
            continue
        }

        $schemaErrors = Test-SafManifestSchema -Manifest $manifest
        $schemaErrors = @($schemaErrors | Where-Object { $_ })
        foreach ($schemaError in $schemaErrors) {
            New-SafCatalogFinding -App $id -Severity 'Error' -Check 'schema' -Message $schemaError
        }
        if ($schemaErrors.Count -gt 0) { continue }

        $manifestHash = [string](Get-SafProp -Object $manifest -Name @('trust', 'value'))
        $lockPath = Join-Path $dir.FullName 'lock.json'
        $lock = $null
        if (Test-Path -LiteralPath $lockPath) {
            try {
                $lock = Read-SafLock -Path $lockPath
            }
            catch {
                New-SafCatalogFinding -App $id -Severity 'Error' -Check 'lock' -Message $_.Exception.Message
            }
        }
        $lockHash = if ($null -ne $lock) { [string]$lock.value } else { '' }

        if ([string]::IsNullOrWhiteSpace($manifestHash) -and [string]::IsNullOrWhiteSpace($lockHash)) {
            New-SafCatalogFinding -App $id -Severity 'Error' -Check 'pin' -Message 'No SHA-256 pin in trust.value or lock.json. A build fails closed unless -TrustOnFirstUse is passed.'
        }
        if ($manifestHash -and $lockHash -and ($manifestHash.ToLowerInvariant() -ne $lockHash.ToLowerInvariant())) {
            New-SafCatalogFinding -App $id -Severity 'Error' -Check 'pin' -Message 'trust.value and lock.json disagree. Update both after reviewing the new installer.'
        }

        $sourceType = [string](Get-SafProp -Object $manifest -Name @('source', 'type'))
        $url = [string](Get-SafProp -Object $manifest -Name @('source', 'url'))
        $fileName = [string](Get-SafProp -Object $manifest -Name @('source', 'fileName'))
        $version = [string](Get-SafProp -Object $manifest -Name @('version'))
        $architecture = [string](Get-SafProp -Object $manifest -Name @('architecture'))

        if ($sourceType -eq 'url') {
            $compact = $version -replace '[^A-Za-z0-9]', ''
            $haystack = "$url $fileName"
            if (-not ($haystack.Contains($version) -or ($compact -and $haystack.Contains($compact)))) {
                New-SafCatalogFinding -App $id -Severity 'Warning' -Check 'version' -Message "Neither source.url nor source.fileName contains version '$version'. A URL without a version can serve a different build later; the hash pin will then fail the build."
            }
            $archMismatch = $false
            switch ($architecture) {
                'x64'   { if ($fileName -match 'x86|win32|arm64') { $archMismatch = $true } }
                'x86'   { if ($fileName -match 'x64|arm64')     { $archMismatch = $true } }
                'arm64' { if ($fileName -match 'x86|x64')       { $archMismatch = $true } }
            }
            if ($archMismatch) {
                New-SafCatalogFinding -App $id -Severity 'Warning' -Check 'architecture' -Message "manifest.architecture is '$architecture' but source.fileName suggests a different architecture. The hash pin only fails later, on a real device."
            }
            if ($null -ne $lock) {
                $lockSource = [string](Get-SafProp -Object $lock -Name @('source'))
                if ($lockSource -and $lockSource -ne $url) {
                    New-SafCatalogFinding -App $id -Severity 'Warning' -Check 'lock' -Message 'lock.json was recorded for a different URL than source.url.'
                }
            }
            if ($url) {
                $key = $url.ToLowerInvariant()
                if ($seenUrls.ContainsKey($key)) {
                    New-SafCatalogFinding -App $id -Severity 'Warning' -Check 'duplicate' -Message ("Same source.url as app '{0}'." -f $seenUrls[$key])
                }
                else {
                    $seenUrls[$key] = $id
                }
            }
        }
        elseif ($sourceType -eq 'evergreen') {
            New-SafCatalogFinding -App $id -Severity 'Info' -Check 'source' -Message 'Evergreen source: the build needs Get-EvergreenApp installed and still requires the exact version and the hash pin.'
        }

        $required = Get-SafProp -Object $manifest -Name @('trust', 'signature', 'required')
        $thumbprint = [string](Get-SafProp -Object $manifest -Name @('trust', 'signature', 'thumbprint'))
        if ($required -ne $true) {
            New-SafCatalogFinding -App $id -Severity 'Info' -Check 'signature' -Message 'No Authenticode requirement. The SHA-256 pin is the only control for this installer.'
        }
        elseif ([string]::IsNullOrWhiteSpace($thumbprint)) {
            New-SafCatalogFinding -App $id -Severity 'Warning' -Check 'signature' -Message 'Signature required without a leaf thumbprint. Any trusted certificate whose subject contains the configured text passes.'
        }

        foreach ($field in @(@('uninstall', 'filePath'), @('detection', 'path'))) {
            $value = [string](Get-SafProp -Object $manifest -Name $field)
            if ($value -and $value -notmatch '^\{(ProgramFiles|ProgramFilesX86|SystemRoot)\}' -and $value -notmatch '^(HKLM|HKEY_LOCAL_MACHINE)') {
                New-SafCatalogFinding -App $id -Severity 'Warning' -Check 'path' -Message ("{0}.{1} does not start with {{ProgramFiles}}, {{ProgramFilesX86}}, {{SystemRoot}}, or HKLM. A fixed drive letter breaks on machines with a different layout." -f $field[0], $field[1])
            }
        }
    }
}

function ConvertTo-SafCatalogMarkdown {
    <#
    .SYNOPSIS
    Renders Test-SafAppCatalog findings as Markdown for a job summary or pull request comment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        $Finding,
        [string[]]$Apps = @()
    )
    begin { $all = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $Finding) { $all.Add($Finding) } }
    end {
        $errors = @($all | Where-Object Severity -eq 'Error').Count
        $warnings = @($all | Where-Object Severity -eq 'Warning').Count
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add('## Secure App Factory catalog check')
        $lines.Add('')
        $scope = if ($Apps.Count -gt 0) { "$($Apps.Count) apps, " } else { '' }
        $lines.Add(("{0}{1} errors, {2} warnings." -f $scope, $errors, $warnings))
        if ($all.Count -gt 0) {
            $lines.Add('')
            $lines.Add('| App | Severity | Check | Message |')
            $lines.Add('| --- | --- | --- | --- |')
            foreach ($item in $all) {
                $message = ([string]$item.Message).Replace('|', '\|')
                $lines.Add(("| {0} | {1} | {2} | {3} |" -f $item.App, $item.Severity, $item.Check, $message))
            }
        }
        return ($lines -join "`n")
    }
}
