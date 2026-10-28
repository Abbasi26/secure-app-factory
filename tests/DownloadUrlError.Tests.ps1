BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force
}

Describe 'Rejected download URL errors' {
    It 'omits the rejected URL and preserves the destination for <Label>' -ForEach @(
        @{ Label = 'embedded credentials'; Url = 'https://user:fictional-secret@example.invalid/setup.exe' }
        @{ Label = 'HTTP with query'; Url = 'http://example.invalid/setup.exe?token=fictional-secret' }
    ) {
        $destination = Join-Path $TestDrive 'installer.bin'
        Set-Content -LiteralPath $destination -Value 'existing installer' -NoNewline

        InModuleScope SecureAppFactory -Parameters @{
            Url = $Url
            Destination = $destination
        } {
            param($Url, $Destination)

            $called = @{ Value = $false }
            $client = {
                param($Request)
                $called.Value = $true
            }
            $message = $null
            try {
                Invoke-SafDownloadFile -Uri $Url -Destination $Destination -WebClient $client
            }
            catch {
                $message = $_.Exception.Message
            }

            $message | Should -BeExactly 'Refusing to download a URL that is not https, or that embeds credentials.'
            $called.Value | Should -BeFalse
            Get-Content -LiteralPath $Destination -Raw | Should -BeExactly 'existing installer'
        }
    }
}

