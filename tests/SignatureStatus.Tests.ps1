BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force
}

Describe 'Authenticode status acceptance' {
    It 'rejects <Label> for pinned trust and trust on first use' -ForEach @(
        @{ Label = 'null'; Status = $null }
        @{ Label = 'empty'; Status = '' }
        @{ Label = 'whitespace'; Status = ' ' }
        @{ Label = 'unknown'; Status = 'FutureStatus' }
        @{ Label = 'unsupported'; Status = 'NotSupported' }
        @{ Label = 'hash mismatch'; Status = 'HashMismatch' }
        @{ Label = 'untrusted'; Status = 'NotTrusted' }
        @{ Label = 'unknown error'; Status = 'UnknownError' }
        @{ Label = 'incompatible'; Status = 'Incompatible' }
    ) {
        $file = Join-Path $TestDrive 'installer.bin'
        Set-Content -LiteralPath $file -Value 'fixture' -NoNewline
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        $manifest = @{
            trust = @{
                value = $hash
                signature = @{ required = $false }
            }
        }
        $inspector = {
            param($Path)
            [pscustomobject]@{
                Status = $Status
                Subject = ''
                Thumbprint = ''
                Platform = 'Test'
            }
        }.GetNewClosure()

        $result = Test-InstallerTrust -Path $file -Manifest $manifest -SignatureInspector $inspector

        $result.Hash.Match | Should -BeTrue
        $result.Passed | Should -BeFalse
        $result.Signature.Match | Should -BeFalse
        $result.Reasons | Should -Contain "Authenticode status is $Status."

        $manifest.trust.Remove('value')
        $lock = Join-Path $TestDrive 'lock.json'
        $result = Test-InstallerTrust -Path $file -Manifest $manifest -SignatureInspector $inspector -LockPath $lock -TrustOnFirstUse

        $result.Passed | Should -BeFalse
        $result.Signature.Match | Should -BeFalse
        $result.LockAction | Should -Be 'preview'
        Test-Path -LiteralPath $lock | Should -BeFalse
    }

    It 'preserves optional-signature acceptance for <Status>' -ForEach @(
        @{ Status = 'Valid' }
        @{ Status = 'NotSigned' }
        @{ Status = 'Unavailable' }
    ) {
        $file = Join-Path $TestDrive 'allowed.bin'
        Set-Content -LiteralPath $file -Value 'fixture' -NoNewline
        $manifest = @{
            trust = @{
                value = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
                signature = @{ required = $false }
            }
        }
        $inspector = {
            param($Path)
            [pscustomobject]@{
                Status = $Status
                Subject = ''
                Thumbprint = ''
                Platform = 'Test'
            }
        }.GetNewClosure()

        $result = Test-InstallerTrust -Path $file -Manifest $manifest -SignatureInspector $inspector

        $result.Hash.Match | Should -BeTrue
        $result.Signature.Match | Should -BeTrue
        $result.Passed | Should -BeTrue
    }
}

