function New-PackageSbom {
    <#
    .SYNOPSIS
        Writes a CycloneDX 1.6 SBOM for the verified installer.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Manifest,
        [Parameter(Mandatory = $true)]
        $Trust,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$SourceUri
    )

    $hash = [string]$Trust.Hash.Actual
    $component = [ordered]@{
        type    = 'application'
        name    = [string]$Manifest.name
        version = [string]$Manifest.version
        purl    = ('pkg:generic/{0}@{1}' -f ([uri]::EscapeDataString([string]$Manifest.name).ToLowerInvariant()), [uri]::EscapeDataString([string]$Manifest.version))
        hashes  = @(
            [ordered]@{
                alg     = 'SHA-256'
                content = $hash
            }
        )
        supplier = [ordered]@{
            name = [string]$Manifest.publisher
        }
    }
    $license = Get-SafProp -Object $Manifest -Name @('license')
    if (-not [string]::IsNullOrWhiteSpace([string]$license)) {
        $component.licenses = @(
            [ordered]@{
                license = [ordered]@{
                    id = [string]$license
                }
            }
        )
    }
    if (-not [string]::IsNullOrWhiteSpace($SourceUri) -and (Test-SafHttpsUrl $SourceUri)) {
        $component.externalReferences = @(
            [ordered]@{
                type = 'distribution'
                url  = $SourceUri
            }
        )
    }
    $component.properties = @(
        [ordered]@{ name = 'secure-app-factory:signature:status'; value = [string]$Trust.Signature.Status },
        [ordered]@{ name = 'secure-app-factory:signature:subject'; value = [string]$Trust.Signature.Subject },
        [ordered]@{ name = 'secure-app-factory:signature:thumbprint'; value = [string]$Trust.Signature.Thumbprint },
        [ordered]@{ name = 'secure-app-factory:demo'; value = ([string]([bool]$Trust.Demo)).ToLowerInvariant() },
        [ordered]@{ name = 'secure-app-factory:hash-source'; value = [string]$Trust.Hash.Source }
    )

    $bom = [ordered]@{
        bomFormat    = 'CycloneDX'
        specVersion  = '1.6'
        serialNumber = 'urn:uuid:' + [guid]::NewGuid().ToString()
        version      = 1
        metadata     = [ordered]@{
            timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
            tools     = [ordered]@{
                components = @(
                    [ordered]@{
                        type    = 'application'
                        name    = 'Secure App Factory'
                        version = [string]$script:SafVersion
                    }
                )
            }
            component = [ordered]@{
                type    = 'application'
                name    = [string]$Manifest.name
                version = [string]$Manifest.version
            }
        }
        components = @($component)
    }

    Write-SafJsonFile -Path $Path -Value $bom
    return [pscustomobject]@{
        Path         = $Path
        Format       = 'CycloneDX'
        SpecVersion  = '1.6'
        Sha256       = (Get-SafSha256 -Path $Path)
    }
}

function New-PackageProvenance {
    <#
    .SYNOPSIS
        Writes a local provenance record for one package build.

    .DESCRIPTION
        The file records the builder, the installer digest, and the SBOM digest.
        It is not an in-toto statement and it is not a SLSA attestation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Manifest,
        [Parameter(Mandatory = $true)]
        $Trust,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$SourceUri,
        [string]$SbomPath,
        [string]$ManifestPath,
        [string]$ScriptPath,
        [bool]$Demo = $false
    )

    $materials = New-Object System.Collections.Generic.List[object]
    $materials.Add([ordered]@{
        uri    = $(if ($SourceUri) { $SourceUri } else { 'unknown' })
        digest = [ordered]@{ sha256 = [string]$Trust.Hash.Actual }
        signature = [ordered]@{
            status     = [string]$Trust.Signature.Status
            subject    = [string]$Trust.Signature.Subject
            thumbprint = [string]$Trust.Signature.Thumbprint
            platform   = [string]$Trust.Signature.Platform
            mock       = [bool]$Trust.Signature.Mock
        }
    })
    if ($SbomPath -and (Test-Path -LiteralPath $SbomPath)) {
        $materials.Add([ordered]@{
            uri    = (Split-Path -Leaf $SbomPath)
            digest = [ordered]@{ sha256 = (Get-SafSha256 -Path $SbomPath) }
        })
    }
    if ($ManifestPath -and (Test-Path -LiteralPath $ManifestPath)) {
        $materials.Add([ordered]@{
            uri    = (Split-Path -Leaf $ManifestPath)
            digest = [ordered]@{ sha256 = (Get-SafSha256 -Path $ManifestPath) }
        })
    }
    if ($ScriptPath -and (Test-Path -LiteralPath $ScriptPath)) {
        $materials.Add([ordered]@{
            uri    = (Split-Path -Leaf $ScriptPath)
            digest = [ordered]@{ sha256 = (Get-SafSha256 -Path $ScriptPath) }
        })
    }

    $record = [ordered]@{
        schema    = 'secure-app-factory.provenance.v0.1'
        note      = 'Local build record. This is not an in-toto statement and not a SLSA attestation.'
        builder   = [ordered]@{
            name    = 'Secure App Factory'
            version = [string]$script:SafVersion
        }
        buildType = 'secure-app-factory.pipeline.v0.1'
        timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        demo      = $Demo
        subject   = [ordered]@{
            name    = [string]$Manifest.name
            version = [string]$Manifest.version
        }
        materials = $materials.ToArray()
        invocation = [ordered]@{
            workflow   = [string]$env:GITHUB_WORKFLOW
            repository = [string]$env:GITHUB_REPOSITORY
            sha        = [string]$env:GITHUB_SHA
            runId      = [string]$env:GITHUB_RUN_ID
            runAttempt = [string]$env:GITHUB_RUN_ATTEMPT
        }
    }
    Write-SafJsonFile -Path $Path -Value $record
    return [pscustomobject]@{
        Path   = $Path
        Schema = 'secure-app-factory.provenance.v0.1'
    }
}
