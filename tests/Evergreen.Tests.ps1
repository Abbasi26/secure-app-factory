BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force

    # Fictional 64-character SHA-256-style hashes; no real artifact bytes are touched.
    $script:PinHash = ('a' * 64)
    $script:OtherHash = ('b' * 64)
}

Describe 'Evergreen candidate selection' {
    BeforeEach {
        $script:Manifest = @{
            version = '1.2.3'
            architecture = 'x64'
            source = @{
                type          = 'evergreen'
                application   = 'ExampleApp'
                fileName      = 'ExampleApp-1.2.3-x64.msi'
                url           = 'https://cdn.example.invalid/ExampleApp-1.2.3-x64.msi'
                pinHash       = $script:PinHash
                architecture  = 'x64'
                installerType = 'msi'
            }
        }
    }

    It 'selects the candidate with the pinned version and matching architecture' {
        $candidates = @(
            [pscustomobject]@{ Version = '1.2.2'; URI = 'https://cdn.example.invalid/ExampleApp-1.2.2-x64.msi'; Architecture = 'x64'; Type = 'msi' }
            [pscustomobject]@{ Version = '1.2.3'; URI = 'https://cdn.example.invalid/ExampleApp-1.2.3-x64.msi'; Architecture = 'x64'; Type = 'msi' }
        )
        $selected = InModuleScope SecureAppFactory -Parameters @{ Manifest = $script:Manifest; Candidates = $candidates } {
            param($Manifest, $Candidates)
            Select-SafEvergreenCandidate -Manifest $Manifest -Candidates $Candidates
        }
        $selected.Version | Should -BeExactly '1.2.3'
        $selected.URI | Should -BeExactly 'https://cdn.example.invalid/ExampleApp-1.2.3-x64.msi'
    }

    It 'falls back to manifest.architecture when source.architecture is absent' {
        $Manifest = @{
            version      = '2.0.0'
            architecture = 'arm64'
            source       = @{ type = 'evergreen'; installerType = 'msi' }
        }
        $candidates = @(
            [pscustomobject]@{ Version = '2.0.0'; URI = 'https://cdn.example.invalid/App-2.0.0-x64.msi'; Architecture = 'x64'; Type = 'msi' }
            [pscustomobject]@{ Version = '2.0.0'; URI = 'https://cdn.example.invalid/App-2.0.0-arm64.msi'; Architecture = 'arm64'; Type = 'msi' }
        )
        $selected = InModuleScope SecureAppFactory -Parameters @{ Manifest = $Manifest; Candidates = $candidates } {
            param($Manifest, $Candidates)
            Select-SafEvergreenCandidate -Manifest $Manifest -Candidates $Candidates
        }
        $selected.URI | Should -BeExactly 'https://cdn.example.invalid/App-2.0.0-arm64.msi'
    }

    It 'filters out candidates with a different architecture or installer type' {
        $candidates = @(
            [pscustomobject]@{ Version = '1.2.3'; URI = 'https://cdn.example.invalid/ExampleApp-1.2.3-x86.msi'; Architecture = 'x86'; Type = 'msi' }
            [pscustomobject]@{ Version = '1.2.3'; URI = 'https://cdn.example.invalid/ExampleApp-1.2.3-arm64.msi'; Architecture = 'arm64'; Type = 'msi' }
            [pscustomobject]@{ Version = '1.2.3'; URI = 'https://cdn.example.invalid/ExampleApp-1.2.3-x64.exe'; Architecture = 'x64'; Type = 'exe' }
            [pscustomobject]@{ Version = '1.2.3'; URI = 'https://cdn.example.invalid/ExampleApp-1.2.3-x64.msi'; Architecture = 'x64'; Type = 'msi' }
        )
        $selected = InModuleScope SecureAppFactory -Parameters @{ Manifest = $script:Manifest; Candidates = $candidates } {
            param($Manifest, $Candidates)
            Select-SafEvergreenCandidate -Manifest $Manifest -Candidates $Candidates
        }
        $selected.URI | Should -BeExactly 'https://cdn.example.invalid/ExampleApp-1.2.3-x64.msi'
    }

    It 'throws when no candidate matches the pinned version' {
        $candidates = @(
            [pscustomobject]@{ Version = '1.3.0'; URI = 'https://cdn.example.invalid/ExampleApp-1.3.0-x64.msi'; Architecture = 'x64'; Type = 'msi' }
        )
        $message = InModuleScope SecureAppFactory -Parameters @{ Manifest = $script:Manifest; Candidates = $candidates } {
            param($Manifest, $Candidates)
            try {
                Select-SafEvergreenCandidate -Manifest $Manifest -Candidates $Candidates
            }
            catch {
                $_.Exception.Message
            }
        }
        $message | Should -Match 'A newer vendor release does not replace the pin'
        $message | Should -Match '1\.2\.3'
        $message | Should -Match '1\.3\.0 https://cdn\.example\.invalid/ExampleApp-1\.3\.0-x64\.msi'
    }

    It 'throws when two candidates share the pinned version and architecture' {
        $candidates = @(
            [pscustomobject]@{ Version = '1.2.3'; URI = 'https://cdn.example.invalid/ExampleApp-1.2.3-a.msi'; Architecture = 'x64'; Type = 'msi' }
            [pscustomobject]@{ Version = '1.2.3'; URI = 'https://cdn.example.invalid/ExampleApp-1.2.3-b.msi'; Architecture = 'x64'; Type = 'msi' }
        )
        $message = InModuleScope SecureAppFactory -Parameters @{ Manifest = $script:Manifest; Candidates = $candidates } {
            param($Manifest, $Candidates)
            try {
                Select-SafEvergreenCandidate -Manifest $Manifest -Candidates $Candidates
            }
            catch {
                $_.Exception.Message
            }
        }
        $message | Should -Match 'Evergreen returned 2 installers for version 1\.2\.3'
        $message | Should -Match 'Pin a source URL instead'
    }
}

Describe 'Get-SourceInstaller with an Evergreen source' {
    It 'downloads the selected candidate over https and reports the resolved URI' {
        $destination = Join-Path $TestDrive 'ExampleApp-1.2.3-x64.msi'
        $manifest = @{
            version = '1.2.3'
            source  = @{
                type          = 'evergreen'
                application   = 'ExampleApp'
                architecture  = 'x64'
                installerType = 'msi'
                fileName      = 'ExampleApp-1.2.3-x64.msi'
                pinHash       = $script:PinHash
            }
        }
        $invoker = {
            param($m)
            @(
                [pscustomobject]@{ Version = '1.2.3'; URI = 'https://cdn.example.invalid/ExampleApp-1.2.3-x64.msi'; Architecture = 'x64'; Type = 'msi' }
            )
        }
        $client = {
            param($request)
            Set-Content -LiteralPath $request.Destination -Value 'fictional installer body' -NoNewline
        }
        $result = InModuleScope SecureAppFactory -Parameters @{
            Manifest = $manifest
            Destination = $destination
            EvergreenInvoker = $invoker
            WebClient = $client
        } {
            param($Manifest, $Destination, $EvergreenInvoker, $WebClient)
            Get-SourceInstaller -Manifest $Manifest -Destination $Destination -EvergreenInvoker $EvergreenInvoker -WebClient $WebClient
        }
        $result.Demo | Should -BeFalse
        $result.SourceUri | Should -BeExactly 'https://cdn.example.invalid/ExampleApp-1.2.3-x64.msi'
        $result.FileName | Should -BeExactly 'ExampleApp-1.2.3-x64.msi'
        Test-Path -LiteralPath $destination | Should -BeTrue
        Get-Content -LiteralPath $destination -Raw | Should -BeExactly 'fictional installer body'
    }

    It 'keeps demo mode unchanged and never calls the evergreen invoker' {
        $fixture = Join-Path $TestDrive 'fixture.msi'
        Set-Content -LiteralPath $fixture -Value 'demo fixture' -NoNewline
        $destination = Join-Path $TestDrive 'demo-installer.msi'
        $manifest = @{
            version = '1.2.3'
            source  = @{
                type     = 'evergreen'
                fileName = 'demo-installer.msi'
            }
        }
        $called = @{ Value = $false }
        $invoker = {
            param($m)
            $called.Value = $true
            @()
        }.GetNewClosure()
        $result = InModuleScope SecureAppFactory -Parameters @{
            Manifest = $manifest
            Destination = $destination
            FixturePath = $fixture
            EvergreenInvoker = $invoker
        } {
            param($Manifest, $Destination, $FixturePath, $EvergreenInvoker)
            Get-SourceInstaller -Manifest $Manifest -Destination $Destination -Demo -FixturePath $FixturePath -EvergreenInvoker $EvergreenInvoker
        }
        $result.Demo | Should -BeTrue
        $result.SourceUri | Should -BeExactly 'demo-fixture'
        $called.Value | Should -BeFalse
        Get-Content -LiteralPath $destination -Raw | Should -BeExactly 'demo fixture'
    }

    It 'rejects a non-https candidate URL via the download guard' {
        $destination = Join-Path $TestDrive 'insecure.msi'
        $manifest = @{
            version = '1.2.3'
            source  = @{
                type          = 'evergreen'
                application   = 'ExampleApp'
                architecture  = 'x64'
                installerType = 'msi'
                fileName      = 'insecure.msi'
            }
        }
        $invoker = {
            param($m)
            @(
                [pscustomobject]@{ Version = '1.2.3'; URI = 'http://cdn.example.invalid/ExampleApp-1.2.3-x64.msi'; Architecture = 'x64'; Type = 'msi' }
            )
        }
        $client = {
            param($request)
            Set-Content -LiteralPath $request.Destination -Value 'should not be written' -NoNewline
        }
        $message = InModuleScope SecureAppFactory -Parameters @{
            Manifest = $manifest
            Destination = $destination
            EvergreenInvoker = $invoker
            WebClient = $client
        } {
            param($Manifest, $Destination, $EvergreenInvoker, $WebClient)
            try {
                Get-SourceInstaller -Manifest $Manifest -Destination $Destination -EvergreenInvoker $EvergreenInvoker -WebClient $WebClient
            }
            catch {
                $_.Exception.Message
            }
        }
        $message | Should -BeExactly 'Refusing to download a URL that is not https, or that embeds credentials.'
        Test-Path -LiteralPath $destination | Should -BeFalse
    }
}