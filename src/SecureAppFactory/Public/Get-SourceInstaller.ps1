function Select-SafEvergreenCandidate {
    param($Manifest, $Candidates)

    $wantedArch = [string](Get-SafProp -Object $Manifest -Name @('source', 'architecture'))
    if ([string]::IsNullOrWhiteSpace($wantedArch)) {
        $wantedArch = [string]$Manifest.architecture
    }
    $wantedType = [string](Get-SafProp -Object $Manifest -Name @('source', 'installerType'))
    $matches = New-Object System.Collections.Generic.List[object]

    foreach ($candidate in @($Candidates)) {
        if ($null -eq $candidate) { continue }
        $arch = [string](Get-SafProp -Object $candidate -Name @('Architecture'))
        if ([string]::IsNullOrWhiteSpace($arch)) {
            $arch = [string](Get-SafProp -Object $candidate -Name @('architecture'))
        }
        $type = [string](Get-SafProp -Object $candidate -Name @('Type'))
        if ([string]::IsNullOrWhiteSpace($type)) {
            $type = [string](Get-SafProp -Object $candidate -Name @('installerType'))
        }
        if (-not [string]::IsNullOrWhiteSpace($wantedArch) -and -not [string]::IsNullOrWhiteSpace($arch) -and ($arch -ne $wantedArch)) {
            continue
        }
        if (-not [string]::IsNullOrWhiteSpace($wantedType) -and -not [string]::IsNullOrWhiteSpace($type) -and ($type -ne $wantedType)) {
            continue
        }
        $uri = [string](Get-SafProp -Object $candidate -Name @('URI'))
        if ([string]::IsNullOrWhiteSpace($uri)) {
            $uri = [string](Get-SafProp -Object $candidate -Name @('Uri'))
        }
        $version = [string](Get-SafProp -Object $candidate -Name @('Version'))
        if ([string]::IsNullOrWhiteSpace($uri) -or [string]::IsNullOrWhiteSpace($version)) {
            continue
        }
        $matches.Add([pscustomobject]@{ Version = $version; URI = $uri })
    }

    $exact = @($matches | Where-Object { $_.Version -eq [string]$Manifest.version })
    if ($exact.Count -eq 1) {
        return $exact[0]
    }
    if ($exact.Count -gt 1) {
        throw "Evergreen returned $($exact.Count) installers for version $($Manifest.version). Pin a source URL instead."
    }
    $seen = @($matches | ForEach-Object { "$($_.Version) $($_.URI)" })
    $seenText = '(none)'
    if ($seen.Count -gt 0) { $seenText = $seen -join '; ' }
    throw "Evergreen did not return the pinned version $($Manifest.version). A newer vendor release does not replace the pin on its own. Candidates: $seenText"
}

function Get-SourceInstaller {
    <#
    .SYNOPSIS
        Copies a demo fixture or downloads the pinned vendor installer.

    .DESCRIPTION
        The installer is written to disk and is not executed. Demo mode copies a local fixture and does not use the network.
        An Evergreen source calls Get-EvergreenApp only when that command is already installed. This module does not install gallery modules.

    .PARAMETER Manifest
        Parsed app manifest.

    .PARAMETER Destination
        File path to write, or a directory. A directory receives source.fileName.

    .PARAMETER Demo
        Copy FixturePath instead of downloading.

    .PARAMETER WebClient
        Optional script block used in tests. It receives Uri and Destination.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Manifest,
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [switch]$Demo,
        [string]$FixturePath,
        [scriptblock]$WebClient,
        [scriptblock]$EvergreenInvoker,
        [int64]$MaximumBytes = 209715200
    )

    $fileName = [string]$Manifest.source.fileName
    $target = $Destination
    if (Test-Path -LiteralPath $Destination -PathType Container) {
        $target = Join-Path $Destination $fileName
    }
    $parent = Split-Path -Parent $target
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $sourceUri = [string](Get-SafProp -Object $Manifest -Name @('source', 'url'))
    if ($Demo) {
        if ([string]::IsNullOrWhiteSpace($FixturePath) -or -not (Test-Path -LiteralPath $FixturePath)) {
            throw "Demo mode requires a local fixture file. Missing: $FixturePath"
        }
        Copy-Item -LiteralPath $FixturePath -Destination $target -Force
        return [pscustomobject]@{
            Path      = $target
            FileName  = $fileName
            SourceUri = 'demo-fixture'
            Demo      = $true
            Bytes     = (Get-Item -LiteralPath $target).Length
        }
    }

    $sourceType = [string]$Manifest.source.type
    if ($sourceType -eq 'evergreen') {
        if ($EvergreenInvoker) {
            $candidates = & $EvergreenInvoker $Manifest
        }
        else {
            $command = Get-Command -Name Get-EvergreenApp -ErrorAction SilentlyContinue
            if (-not $command) {
                throw 'An Evergreen source needs Get-EvergreenApp on the module path. Install the Evergreen module yourself; Secure App Factory does not install gallery modules.'
            }
            $candidates = @(Get-EvergreenApp -Name ([string]$Manifest.source.application))
        }
        $selected = Select-SafEvergreenCandidate -Manifest $Manifest -Candidates $candidates
        $sourceUri = [string]$selected.URI
    }

    if ([string]::IsNullOrWhiteSpace($sourceUri)) {
        throw 'The manifest does not resolve to a download URL.'
    }
    Invoke-SafDownloadFile -Uri $sourceUri -Destination $target -WebClient $WebClient -MaximumBytes $MaximumBytes
    return [pscustomobject]@{
        Path      = $target
        FileName  = $fileName
        SourceUri = $sourceUri
        Demo      = $false
        Bytes     = (Get-Item -LiteralPath $target).Length
    }
}
