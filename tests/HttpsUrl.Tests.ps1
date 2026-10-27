BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force
}

Describe 'HTTPS URL validation' {
    It 'validates <Label>' -ForEach @(
        @{ Label = 'null'; Url = $null; Expected = $false }
        @{ Label = 'empty input'; Url = ''; Expected = $false }
        @{ Label = 'blank input'; Url = ' '; Expected = $false }
        @{ Label = 'missing host'; Url = 'https://'; Expected = $false }
        @{ Label = 'invalid port'; Url = 'https://example.invalid:bad/setup.exe'; Expected = $false }
        @{ Label = 'relative path'; Url = 'setup.exe'; Expected = $false }
        @{ Label = 'HTTP'; Url = 'http://example.invalid/setup.exe'; Expected = $false }
        @{ Label = 'username'; Url = 'https://user@example.invalid/setup.exe'; Expected = $false }
        @{ Label = 'username and password'; Url = 'https://user:secret@example.invalid/setup.exe'; Expected = $false }
        @{ Label = 'HTTPS'; Url = 'https://example.invalid/setup.exe'; Expected = $true }
        @{ Label = 'uppercase scheme and port'; Url = 'HTTPS://example.invalid:8443/setup.exe?x=1#part'; Expected = $true }
    ) {
        $actual = InModuleScope SecureAppFactory -Parameters @{ Url = $Url } {
            param($Url)
            Test-SafHttpsUrl -Url $Url
        }
        $actual | Should -BeOfType ([bool])
        $actual | Should -Be $Expected
    }
}

# Skipped: repository edits and the full test suite; only representative URI parsing was checked.
# Risk: previously accepted malformed URLs will fail earlier; redirect destinations remain unchecked.
