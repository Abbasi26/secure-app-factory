function Resolve-SafDemoFixture {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [string]$FixtureRoot
    )

    $appId = Get-SafAppId -ManifestPath $ManifestPath
    if ([string]::IsNullOrWhiteSpace($FixtureRoot)) {
        $repo = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $ManifestPath) '../..'))
        $FixtureRoot = Join-Path $repo 'demo/fixtures'
    }
    $dir = Join-Path $FixtureRoot $appId
    $installer = Join-Path $dir 'installer.bin'
    $hashFile = Join-Path $dir 'installer.sha256'
    $mockFile = Join-Path $dir 'mock-signature.json'
    foreach ($file in @($installer, $hashFile, $mockFile)) {
        if (-not (Test-Path -LiteralPath $file)) {
            throw "Demo fixture is missing: $file"
        }
    }
    $mock = Get-Content -Raw -LiteralPath $mockFile | ConvertFrom-Json
    return [pscustomobject]@{
        Installer    = $installer
        ExpectedHash = ([System.IO.File]::ReadAllText($hashFile)).Trim()
        Mock         = $mock
    }
}

function Invoke-SafPipeline {
    <#
    .SYNOPSIS
        Runs fetch, trust, packaging, SBOM, provenance, an optional smoke test, and an optional Intune upload.

    .DESCRIPTION
        Writes a Markdown report under -Destination even when a later step fails.
        -Demo uses local fixtures and does not download, install, or upload.
        -SmokeTest, -IncludeToolkit, -DownloadContentPrepTool, -TrustOnFirstUse, and -Upload are the explicit write switches.
        -Upload publishes a Win32 app and does not create an assignment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [switch]$Demo,
        [switch]$Force,
        [switch]$SmokeTest,
        [ValidateSet('Command', 'Toolkit')]
        [string]$SmokeTestMode = 'Command',
        [switch]$IncludeToolkit,
        [switch]$DownloadContentPrepTool,
        [string]$ContentPrepToolPath,
        [switch]$Upload,
        [switch]$TrustOnFirstUse,
        [string]$FixtureRoot,
        [string]$ToolCache,
        [scriptblock]$WebClient,
        [scriptblock]$EvergreenInvoker,
        [scriptblock]$SignatureInspector,
        [scriptblock]$HttpInvoker
    )

    if ($Demo -and ($SmokeTest -or $IncludeToolkit -or $DownloadContentPrepTool -or $Upload -or $TrustOnFirstUse -or $ContentPrepToolPath)) {
        throw 'Demo mode does not install software, download tools, record pins, or upload. Remove the other switches.'
    }

    $destinationFull = Assert-SafDestination -Destination $Destination -ManifestPath $ManifestPath -Force:$Force
    $failed = $null
    $manifest = $null
    $state = @{
        ModuleVersion = [string]$script:SafVersion
        Demo          = [bool]$Demo
        App           = $null
        ManifestPath  = $ManifestPath
        Destination   = $destinationFull
        Trust         = $null
        Psadt         = $null
        IntuneWin     = $null
        Sbom          = $null
        Provenance    = $null
        SmokeTest     = $null
        Upload        = $null
        Error         = $null
    }

    try {
        $manifest = Read-SafManifest -Path $ManifestPath
        $state.App = @{
            Id        = Get-SafAppId -ManifestPath $ManifestPath
            Name      = [string]$manifest.name
            Version   = [string]$manifest.version
            Publisher = [string]$manifest.publisher
        }
        $lockPath = Join-Path (Split-Path -Parent $ManifestPath) 'lock.json'
        $fixture = $null
        $sourceDir = Join-Path $destinationFull 'source'
        if (-not (Test-Path -LiteralPath $sourceDir)) {
            New-Item -ItemType Directory -Path $sourceDir -Force | Out-Null
        }
        $sourceParams = @{
            Manifest    = $manifest
            Destination = $sourceDir
        }
        if ($Demo) {
            $fixture = Resolve-SafDemoFixture -ManifestPath $ManifestPath -FixtureRoot $FixtureRoot
            $sourceParams.Demo = $true
            $sourceParams.FixturePath = $fixture.Installer
        }
        else {
            if ($WebClient) { $sourceParams.WebClient = $WebClient }
            if ($EvergreenInvoker) { $sourceParams.EvergreenInvoker = $EvergreenInvoker }
        }
        $source = Get-SourceInstaller @sourceParams

        $trustParams = @{
            Path     = $source.Path
            Manifest = $manifest
            LockPath = $lockPath
        }
        if ($Demo) {
            $trustParams.Demo = $true
            $trustParams.ExpectedHash = $fixture.ExpectedHash
            $captured = $fixture.Mock
            if (-not $SignatureInspector) {
                $SignatureInspector = {
                    param($FilePath)
                    [pscustomobject]@{
                        Status     = [string]$captured.status
                        Subject    = [string]$captured.subject
                        Thumbprint = [string]$captured.thumbprint
                        Platform   = 'Demo'
                    }
                }.GetNewClosure()
            }
        }
        else {
            if ($TrustOnFirstUse) { $trustParams.TrustOnFirstUse = $true }
        }
        if ($SignatureInspector) { $trustParams.SignatureInspector = $SignatureInspector }
        $trust = Test-InstallerTrust @trustParams
        $state.Trust = $trust
        Write-SafJsonFile -Path (Join-Path $destinationFull 'trust.json') -Value $trust
        if (-not $trust.Passed) {
            throw ('Installer trust check failed: ' + ($trust.Reasons -join ' '))
        }

        $packageParams = @{
            InstallerPath = $source.Path
            Manifest      = $manifest
            Destination   = (Join-Path $destinationFull 'package')
        }
        if ($IncludeToolkit) { $packageParams.IncludeToolkit = $true }
        if (-not [string]::IsNullOrWhiteSpace($ToolCache)) { $packageParams.ToolCache = $ToolCache }
        if ($WebClient -and -not $Demo) { $packageParams.WebClient = $WebClient }
        $package = New-PsadtPackage @packageParams
        $state.Psadt = $package
        $copiedHash = Get-SafSha256 -Path $package.InstallerPath
        if ($copiedHash -ne $trust.Hash.Actual) {
            throw 'The installer copied into the PSADT folder does not match the verified hash.'
        }

        $intuneParams = @{
            SourceFolder = $package.Path
            SetupFile    = 'Invoke-AppDeployToolkit.ps1'
            Destination  = (Join-Path $destinationFull 'intunewin')
        }
        if ($DownloadContentPrepTool) { $intuneParams.DownloadTool = $true }
        if (-not [string]::IsNullOrWhiteSpace($ContentPrepToolPath)) { $intuneParams.ToolPath = $ContentPrepToolPath }
        if (-not [string]::IsNullOrWhiteSpace($ToolCache)) { $intuneParams.ToolCache = $ToolCache }
        if ($WebClient) { $intuneParams.WebClient = $WebClient }
        $intuneWin = New-IntuneWinPackage @intuneParams
        $state.IntuneWin = $intuneWin

        $sbom = New-PackageSbom -Manifest $manifest -Trust $trust -Path (Join-Path $destinationFull 'sbom.cdx.json') -SourceUri $source.SourceUri
        $state.Sbom = $sbom
        $provenance = New-PackageProvenance -Manifest $manifest -Trust $trust -Path (Join-Path $destinationFull 'provenance.json') -SourceUri $source.SourceUri -SbomPath $sbom.Path -ManifestPath $ManifestPath -ScriptPath $package.ScriptPath -Demo:([bool]$Demo)
        $state.Provenance = $provenance

        $smoke = Test-PackageInstall -Manifest $manifest -InstallerPath $source.Path -Mode $SmokeTestMode -PackageRoot $package.Path -SmokeTest:$SmokeTest
        $state.SmokeTest = $smoke

        $intunePath = [string]$intuneWin.Path
        if ($Upload) {
            $uploadResult = Send-IntunePackage -Manifest $manifest -IntuneWinPath $intunePath -Upload -HttpInvoker $HttpInvoker
        }
        else {
            $uploadResult = Send-IntunePackage -Manifest $manifest -IntuneWinPath $intunePath -HttpInvoker $HttpInvoker
        }
        $state.Upload = $uploadResult
        $planToWrite = [ordered]@{
            Status            = [string]$uploadResult.Status
            Reason            = [string]$uploadResult.Reason
            SecretsConfigured = [bool]$uploadResult.SecretsConfigured
            Steps             = @($uploadResult.Steps)
            AppId             = [string]$uploadResult.AppId
            CreatesAssignment = $false
            InstallCommandLine = [string]$uploadResult.Plan.InstallCommandLine
            UninstallCommandLine = [string]$uploadResult.Plan.UninstallCommandLine
        }
        Write-SafJsonFile -Path (Join-Path $destinationFull 'intune-plan.json') -Value $planToWrite
    }
    catch {
        $failed = $_
        $state.Error = $_.Exception.Message
    }
    finally {
        $reportPath = Join-Path $destinationFull 'REPORT.md'
        New-PackageReport -Result $state -Path $reportPath | Out-Null
        $publicState = [ordered]@{
            ModuleVersion = $state.ModuleVersion
            Demo          = $state.Demo
            App           = $state.App
            Destination   = $state.Destination
            ReportPath    = $reportPath
            Error         = $state.Error
            TrustPassed   = $(if ($state.Trust) { [bool]$state.Trust.Passed } else { $false })
            IntuneWin     = $(if ($state.IntuneWin) { [string]$state.IntuneWin.Status } else { '' })
            Upload        = $(if ($state.Upload) { [string]$state.Upload.Status } else { '' })
            SmokeTest     = $(if ($state.SmokeTest) { [string]$state.SmokeTest.Status } else { '' })
        }
        Write-SafJsonFile -Path (Join-Path $destinationFull 'result.json') -Value $publicState
    }

    if ($failed) {
        throw $failed
    }
    return [pscustomobject]@{
        Passed      = $true
        Destination = $destinationFull
        ReportPath  = (Join-Path $destinationFull 'REPORT.md')
        Trust       = $state.Trust
        Psadt       = $state.Psadt
        IntuneWin   = $state.IntuneWin
        Sbom        = $state.Sbom
        Provenance  = $state.Provenance
        SmokeTest   = $state.SmokeTest
        Upload      = $state.Upload
    }
}
