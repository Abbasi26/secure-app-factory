BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force

    $manifest = @{
        install = @{ arguments = '/S' }
        uninstall = @{ filePath = 'uninstall.exe'; arguments = '/S' }
        detection = @{ type = 'file'; path = 'installed.exe' }
    }
}

Describe 'Smoke-test timeout validation' {
    It 'rejects <Seconds> seconds before execution' -ForEach @(
        @{ Seconds = -1 }
        @{ Seconds = 0 }
        @{ Seconds = 2147484 }
        @{ Seconds = 2147483647 }
    ) {
        {
            Test-PackageInstall -Manifest $manifest -InstallerPath 'setup.exe' -TimeoutSeconds $Seconds
        } | Should -Throw -ErrorId 'ParameterArgumentValidationError,Test-PackageInstall'

        InModuleScope SecureAppFactory -Parameters @{ Seconds = $Seconds } {
            param($Seconds)

            Mock Test-Path { throw 'Parameter validation must run first.' }

            {
                Invoke-SafCheckedProcess -FilePath 'setup.exe' -Arguments '/S' -TimeoutSeconds $Seconds
            } | Should -Throw -ErrorId 'ParameterArgumentValidationError,Invoke-SafCheckedProcess'

            Should -Invoke Test-Path -Times 0 -Exactly
        }
    }

    It 'accepts <Seconds> seconds in preview' -ForEach @(
        @{ Seconds = 1 }
        @{ Seconds = 600 }
        @{ Seconds = 2147483 }
    ) {
        $result = Test-PackageInstall -Manifest $manifest -InstallerPath 'setup.exe' -TimeoutSeconds $Seconds

        $result.Status | Should -Be 'Preview'
        $result.Executed | Should -BeFalse
    }
}

# Skipped: repository edits, test execution, and unrelated smoke-test changes.
# Risk: callers passing zero, negative, or overflowing timeouts now fail immediately.
