BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force
}

Describe 'Smoke-test detection delay validation' {
    It 'rejects negative delays before execution in preview and smoke-test modes' {
        InModuleScope SecureAppFactory {
            $manifest = @{
                install = @{ arguments = '/S' }
                uninstall = @{ filePath = 'uninstall.exe'; arguments = '/S' }
                detection = @{ type = 'file'; path = 'installed.exe' }
            }

            Mock Invoke-SafCheckedProcess { throw 'Execution must not occur.' }

            foreach ($seconds in @(-1, [int]::MinValue)) {
                foreach ($execute in @($false, $true)) {
                    {
                        Test-PackageInstall -Manifest $manifest -InstallerPath 'setup.exe' -DetectionDelaySeconds $seconds -SmokeTest:$execute
                    } | Should -Throw -ErrorId 'ParameterArgumentValidationError,Test-PackageInstall'
                }
            }

            Should -Invoke Invoke-SafCheckedProcess -Times 0 -Exactly
        }
    }

    It 'accepts nonnegative delays and the omitted default in preview' {
        $manifest = @{
            install = @{ arguments = '/S' }
            uninstall = @{ filePath = 'uninstall.exe'; arguments = '/S' }
            detection = @{ type = 'file'; path = 'installed.exe' }
        }

        foreach ($parameters in @(
            @{}
            @{ DetectionDelaySeconds = 0 }
            @{ DetectionDelaySeconds = 2 }
            @{ DetectionDelaySeconds = [int]::MaxValue }
        )) {
            $result = Test-PackageInstall -Manifest $manifest -InstallerPath 'setup.exe' @parameters
            $result.Status | Should -Be 'Preview'
            $result.Executed | Should -BeFalse
        }
    }
}
