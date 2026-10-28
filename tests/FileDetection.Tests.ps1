BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force
}

Describe 'File detection' {
    It 'requires an existing file and treats its path literally' {
        $file = Join-Path $TestDrive 'installed[1].exe'
        $directory = Join-Path $TestDrive 'directory.exe'
        $missing = Join-Path $TestDrive 'missing.exe'
        [System.IO.File]::WriteAllText($file, 'fixture')
        [System.IO.Directory]::CreateDirectory($directory) | Out-Null

        foreach ($case in @(
            @{ Path = $file; Expected = $true }
            @{ Path = $directory; Expected = $false }
            @{ Path = $missing; Expected = $false }
        )) {
            $actual = InModuleScope SecureAppFactory -Parameters @{ Path = $case.Path } {
                param($Path)
                Test-SafDetection -Manifest @{
                    detection = @{ type = 'file'; path = $Path }
                }
            }
            $actual | Should -BeOfType ([bool])
            $actual | Should -Be $case.Expected
        }
    }
}
