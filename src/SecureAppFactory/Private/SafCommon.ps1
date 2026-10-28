# Shared helpers. None of these contact the network.

function Get-SafProp {
    param(
        $Object,
        [Parameter(Mandatory = $true)]
        [string[]]$Name
    )

    $current = $Object
    foreach ($part in $Name) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($part)) { return $null }
            $current = $current[$part]
            continue
        }
        $property = $current.PSObject.Properties[$part]
        if ($null -eq $property) { return $null }
        $current = $property.Value
    }
    return $current
}

function Test-SafHasProp {
    param(
        $Object,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) {
        return $Object.Contains($Name)
    }
    return $null -ne $Object.PSObject.Properties[$Name]
}

function Write-SafTextFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    if (-not $Text.EndsWith("`n")) {
        $Text += "`n"
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}

function ConvertTo-SafJson {
    param($Value)
    return (ConvertTo-Json -InputObject $Value -Depth 30)
}

function Write-SafJsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        $Value
    )
    Write-SafTextFile -Path $Path -Text (ConvertTo-SafJson -Value $Value)
}

function Get-SafSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $Path
    return $hash.Hash.ToLowerInvariant()
}

function ConvertTo-SafHex {
    param([AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return (($Value -replace '[^A-Fa-f0-9]', '').ToLowerInvariant())
}

function Format-SafSingleQuoted {
    param([AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { $Value = '' }
    return "'" + ($Value -replace "'", "''") + "'"
}

function Get-SafExternalTools {
    $path = Join-Path $script:SafRoot 'data/external-tools.json'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "External tool pin file is missing: $path"
    }
    return (Get-Content -Raw -LiteralPath $path | ConvertFrom-Json)
}

function Test-SafHttpsUrl {
    param([AllowEmptyString()][string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
    $parsed = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$parsed)) {
        return $false
    }
    return $parsed.Scheme -eq 'https' -and
        -not [string]::IsNullOrEmpty($parsed.Host) -and
        [string]::IsNullOrEmpty($parsed.UserInfo)
}

function Expand-SafMachinePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $programFiles = $env:ProgramFiles
    if ([string]::IsNullOrWhiteSpace($programFiles)) { $programFiles = 'C:\Program Files' }
    $programFilesX86 = ${env:ProgramFiles(x86)}
    if ([string]::IsNullOrWhiteSpace($programFilesX86)) { $programFilesX86 = 'C:\Program Files (x86)' }
    $systemRoot = $env:SystemRoot
    if ([string]::IsNullOrWhiteSpace($systemRoot)) { $systemRoot = 'C:\Windows' }

    return $Path.Replace('{ProgramFilesX86}', $programFilesX86).Replace('{ProgramFiles}', $programFiles).Replace('{SystemRoot}', $systemRoot)
}

function Expand-SafIntunePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return $Path.Replace('{ProgramFilesX86}', 'C:\Program Files (x86)').Replace('{ProgramFiles}', 'C:\Program Files').Replace('{SystemRoot}', 'C:\Windows')
}

function Format-SafRuntimePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = @(
        @{ Token = '{ProgramFilesX86}'; Expression = '${env:ProgramFiles(x86)}' },
        @{ Token = '{ProgramFiles}'; Expression = '$env:ProgramFiles' },
        @{ Token = '{SystemRoot}'; Expression = '$env:SystemRoot' }
    )
    foreach ($token in $tokens) {
        if ($Path -eq $token.Token) {
            return $token.Expression
        }
        $prefix = $token.Token + '\'
        if ($Path.StartsWith($prefix)) {
            $rest = $Path.Substring($prefix.Length)
            return '(Join-Path -Path ' + $token.Expression + ' -ChildPath ' + (Format-SafSingleQuoted $rest) + ')'
        }
    }
    return (Format-SafSingleQuoted $Path)
}

function Get-SafAppId {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)
    $appDir = Split-Path -Parent $ManifestPath
    return (Split-Path -Leaf $appDir)
}

function Assert-SafDestination {
    param(
        [Parameter(Mandatory = $true)][string]$Destination,
        [string]$ManifestPath,
        [switch]$Force
    )

    $full = [System.IO.Path]::GetFullPath($Destination)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.TrimEnd('\', '/') -eq $root.TrimEnd('\', '/')) {
        throw "Refusing to use a drive root as the destination: $full"
    }
    if ($ManifestPath) {
        $appDir = Split-Path -Parent $ManifestPath
        $repo = [System.IO.Path]::GetFullPath((Join-Path $appDir '../..'))
        if ($full.TrimEnd('\', '/') -eq $repo.TrimEnd('\', '/')) {
            throw 'Refusing to use the repository root as the destination.'
        }
    }
    $exists = Test-Path -LiteralPath $full
    if ($exists) {
        $child = Get-ChildItem -LiteralPath $full -Force | Select-Object -First 1
        if ($child -and -not $Force) {
            throw "Destination exists and is not empty. Pass -Force to replace it: $full"
        }
        if ($Force) {
            Remove-Item -LiteralPath $full -Recurse -Force
        }
    }
    New-Item -ItemType Directory -Path $full -Force | Out-Null
    return $full
}

function Invoke-SafDownloadFile {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination,
        [scriptblock]$WebClient,
        [int64]$MaximumBytes = 209715200
    )

    if (-not (Test-SafHttpsUrl $Uri)) {
        throw "Refusing to download a URL that is not https, or that embeds credentials: $Uri"
    }
    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Force
    }

    if ($WebClient) {
        & $WebClient @{ Uri = $Uri; Destination = $Destination }
    }
    else {
        Invoke-WebRequest -Uri $Uri -OutFile $Destination -UseBasicParsing -UserAgent "SecureAppFactory/$($script:SafVersion)"
    }

    if (-not (Test-Path -LiteralPath $Destination)) {
        throw "Download did not create a file: $Uri"
    }
    $length = (Get-Item -LiteralPath $Destination).Length
    if ($length -gt $MaximumBytes) {
        Remove-Item -LiteralPath $Destination -Force
        throw "Download exceeds the maximum size of $MaximumBytes bytes: $Uri"
    }
    if ($length -le 0) {
        Remove-Item -LiteralPath $Destination -Force
        throw "Download was empty: $Uri"
    }
}

function Expand-SafZip {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $destRoot = [System.IO.Path]::GetFullPath($Destination)
    if (-not (Test-Path -LiteralPath $destRoot)) {
        New-Item -ItemType Directory -Path $destRoot -Force | Out-Null
    }
    $prefix = $destRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($entry in $zip.Entries) {
            $relative = ($entry.FullName -replace '\\', '/').TrimStart('/')
            if ([string]::IsNullOrWhiteSpace($relative)) { continue }
            if ($relative.Contains('..')) {
                throw "Refusing zip entry that escapes the destination: $($entry.FullName)"
            }
            $target = [System.IO.Path]::GetFullPath((Join-Path $destRoot $relative))
            if (-not $target.StartsWith($prefix) -and $target -ne $destRoot) {
                throw "Refusing zip entry that escapes the destination: $($entry.FullName)"
            }
            $isDirectory = $entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')
            if ($isDirectory -or [string]::IsNullOrEmpty($entry.Name)) {
                if (-not (Test-Path -LiteralPath $target)) {
                    New-Item -ItemType Directory -Path $target -Force | Out-Null
                }
                continue
            }
            $parent = Split-Path -Parent $target
            if ($parent -and -not (Test-Path -LiteralPath $parent)) {
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
            }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
        }
    }
    finally {
        $zip.Dispose()
    }
}

function Get-SafIsWindows {
    if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) {
        return [bool]$IsWindows
    }
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        return $true
    }
    return $false
}
