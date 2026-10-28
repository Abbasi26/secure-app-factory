BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force
}

Describe 'SHA-256 pin validation' {
    It 'rejects <Label> before signature inspection or lock creation' -ForEach @(
        @{ Label = 'short'; Kind = 'short' }
        @{ Label = 'long'; Kind = 'long' }
        @{ Label = 'non-hex suffix'; Kind = 'suffix' }
        @{ Label = 'leading space'; Kind = 'space' }
        @{ Label = 'embedded separator'; Kind = 'separator' }
        @{ Label = 'trailing newline'; Kind = 'newline' }
    ) {
        $file = Join-Path $TestDrive 'installer.bin'
        Set-Content -LiteralPath $file -Value 'fixture' -NoNewline
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        $bad = switch ($Kind) {
            'short' { $hash.Substring(1) }
            'long' { $hash + '0' }
            'suffix' { $hash + '!' }
            'space' { ' ' + $hash }
            'separator' { $hash.Insert(32, ':') }
            'newline' { $hash + "`n" }
        }

        foreach ($source in @('manifest', 'parameter')) {
            $manifest = @{
                trust = @{
                    signature = @{ required = $false }
                }
            }
            $lock = Join-Path $TestDrive "$Kind-$source-lock.json"
            $parameters = @{
                Path = $file
                Manifest = $manifest
                LockPath = $lock
                TrustOnFirstUse = $true
                SignatureInspector = { throw 'Signature inspection must not run.' }
            }
            if ($source -eq 'manifest') {
                $manifest.trust.value = $bad
            }
            else {
                $parameters.ExpectedHash = $bad
            }

            { Test-InstallerTrust @parameters } |
                Should -Throw -ExpectedMessage 'SHA-256 pin must contain exactly 64 hexadecimal characters.'
            Test-Path -LiteralPath $lock | Should -BeFalse
        }
    }

    It 'accepts and lowercases a valid uppercase ExpectedHash' {
        $file = Join-Path $TestDrive 'valid.bin'
        Set-Content -LiteralPath $file -Value 'fixture' -NoNewline
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToUpperInvariant()
        $manifest = @{
            trust = @{
                signature = @{ required = $false }
            }
        }
        $result = Test-InstallerTrust -Path $file -Manifest $manifest -ExpectedHash $hash -SignatureInspector {
            param($Path)
            [pscustomobject]@{
                Status = 'NotSigned'
                Subject = ''
                Thumbprint = ''
                Platform = 'Test'
            }
        }

        $result.Passed | Should -BeTrue
        $result.Hash.Expected | Should -BeExactly $hash.ToLowerInvariant()
    }

    It 'preserves absent-pin normalization' {
        InModuleScope SecureAppFactory {
            foreach ($value in @($null, '', ' ', "`t`n")) {
                ConvertTo-SafHex -Value $value | Should -BeExactly ''
            }
        }
    }
}
