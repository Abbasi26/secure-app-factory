@{
    ModuleVersion     = '0.2.0'
    GUID              = '7b6e1c2a-4f0d-4e5a-9c31-2a6e8f0b7d14'
    Author            = 'Wasaf Abbasi'
    CompanyName       = 'Wasaf Abbasi'
    Copyright         = '(c) Wasaf Abbasi. Licensed under the MIT License.'
    Description       = 'Build Windows packages for Intune and MECM with hash pinning, Authenticode checks, PSAppDeployToolkit, an .intunewin, a CycloneDX SBOM, and local provenance.'
    PowerShellVersion = '7.0'
    RootModule        = 'SecureAppFactory.psm1'
    FunctionsToExport = @(
        'Get-SourceInstaller',
        'Test-InstallerTrust',
        'New-PsadtPackage',
        'New-IntuneWinPackage',
        'New-PackageSbom',
        'New-PackageProvenance',
        'Test-PackageInstall',
        'Get-IntuneUploadPlan',
        'Send-IntunePackage',
        'New-PackageReport',
        'Invoke-SafPipeline',
        'Test-SafAppCatalog',
        'ConvertTo-SafCatalogMarkdown',
        'New-SafAppManifest'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Intune', 'MECM', 'PSAppDeployToolkit', 'SBOM', 'SupplyChain')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
