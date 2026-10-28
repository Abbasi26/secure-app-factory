BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force
}

Describe 'Smoke-test detection retry validation' {
    It 'rejects nonpositive counts before body work in preview and smoke-test modes' {
        InModuleScope SecureAppFactory {
            $manifest = @{
                install = @{ arguments = '/S' }
                uninstall = @{ filePath = 'uninstall.exe'; arguments = '/S' }
                detection = @{ type = 'file'; path = 'installed.exe' }
            }

            Mock Get-SafDetectionText { throw 'Parameter validation must run first.' }
            Mock Invoke-SafCheckedProcess { throw 'Execution must not occur.' }

            foreach ($retries in @(0, -1, [int]::MinValue)) {
                foreach ($execute in @($false, $true)) {
                    {
                        Test-PackageInstall -Manifest $manifest -InstallerPath 'setup.exe' -DetectionRetries $retries -SmokeTest:$execute
                    } | Should -Throw -ErrorId 'ParameterArgumentValidationError,Test-PackageInstall'
                }
            }

            Should -Invoke Get-SafDetectionText -Times 0 -Exactly
            Should -Invoke Invoke-SafCheckedProcess -Times 0 -Exactly
        }
    }

    It 'accepts positive counts and the omitted default in preview' {
        $manifest = @{
            install = @{ arguments = '/S' }
            uninstall = @{ filePath = 'uninstall.exe'; arguments = '/S' }
            detection = @{ type = 'file'; path = 'installed.exe' }
        }

        foreach ($parameters in @(
            @{}
            @{ DetectionRetries = 1 }
            @{ DetectionRetries = 10 }
            @{ DetectionRetries = [int]::MaxValue }
        )) {
            $result = Test-PackageInstall -Manifest $manifest -InstallerPath 'setup.exe' @parameters
            $result.Status | Should -Be 'Preview'
            $result.Executed | Should -BeFalse
        }
    }
}

