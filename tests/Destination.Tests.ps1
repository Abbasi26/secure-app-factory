BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force
}

Describe 'Repository destination protection' {
    It 'rejects the repository root with trailing separator = <TrailingSeparator>' -ForEach @(
        @{ TrailingSeparator = $false }
        @{ TrailingSeparator = $true }
    ) {
        $repo = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $appDir = Join-Path $repo 'apps/example'
        New-Item -ItemType Directory -Path $appDir -Force | Out-Null
        $sentinel = Join-Path $repo 'keep.txt'
        Set-Content -LiteralPath $sentinel -Value 'keep'

        $destination = $repo
        if ($TrailingSeparator) {
            $destination += [System.IO.Path]::DirectorySeparatorChar
        }

        {
            InModuleScope SecureAppFactory -Parameters @{
                Destination = $destination
                ManifestPath = (Join-Path $appDir 'app.yaml')
            } {
                param($Destination, $ManifestPath)
                Assert-SafDestination -Destination $Destination -ManifestPath $ManifestPath -Force
            }
        } | Should -Throw '*repository root*'

        Get-Content -LiteralPath $sentinel | Should -Be 'keep'
    }
}

# Skipped: repository edits, test execution, and demo execution in this read-only review.
# Risk: ancestor destinations and symbolic-link aliases remain outside this fix.
