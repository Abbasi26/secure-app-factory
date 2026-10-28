BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force
    $script:RepoApps = Join-Path $PSScriptRoot '../apps'
    $script:Hash = 'a' * 64

    function New-TestApp {
        param([string]$Root, [string]$Id, [hashtable]$Overrides = @{})
        $p = @{
            Id               = $Id
            Name             = 'Example Tool'
            Version          = '1.2.3'
            Publisher        = 'Example Publisher'
            Url              = 'https://downloads.example.org/tool/1.2.3/tool-1.2.3-x64.exe'
            Sha256           = $script:Hash
            InstallArguments = '/S'
            UninstallPath    = '{ProgramFiles}\Example Tool\uninstall.exe'
            UninstallArguments = '/S'
            DetectionPath    = '{ProgramFiles}\Example Tool\tool.exe'
            AppsPath         = $Root
        }
        foreach ($key in $Overrides.Keys) { $p[$key] = $Overrides[$key] }
        New-SafAppManifest @p
    }
}

Describe 'Test-SafAppCatalog' {
    It 'finds no errors or warnings in the shipped example apps' {
        $findings = @(Test-SafAppCatalog -Path $script:RepoApps)
        @($findings | Where-Object Severity -in 'Error', 'Warning').Count | Should -Be 0
        @($findings | Where-Object { $_.App -eq '7zip' -and $_.Check -eq 'signature' }).Count | Should -Be 1
    }

    It 'reports a manifest and lock hash mismatch as an error' {
        $root = Join-Path $TestDrive 'mismatch'
        New-TestApp -Root $root -Id 'tool' | Out-Null
        $lockPath = Join-Path $root 'tool/lock.json'
        $lock = Get-Content -Raw $lockPath | ConvertFrom-Json
        $lock.value = 'b' * 64
        $lock | ConvertTo-Json | Set-Content $lockPath
        $findings = @(Test-SafAppCatalog -Path $root)
        @($findings | Where-Object { $_.Severity -eq 'Error' -and $_.Check -eq 'pin' }).Count | Should -Be 1
    }

    It 'reports a missing pin as an error' {
        $root = Join-Path $TestDrive 'nopin'
        New-TestApp -Root $root -Id 'tool' | Out-Null
        Remove-Item (Join-Path $root 'tool/lock.json')
        $yamlPath = Join-Path $root 'tool/app.yaml'
        (Get-Content -Raw $yamlPath) -replace "  value: a{64}\n", '' | Set-Content -NoNewline $yamlPath
        $findings = @(Test-SafAppCatalog -Path $root)
        ($findings | Where-Object Check -eq 'pin').Message | Should -Match 'No SHA-256 pin'
    }

    It 'reports schema errors and unparsable files without stopping at the first app' {
        $root = Join-Path $TestDrive 'schema'
        New-TestApp -Root $root -Id 'good' | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $root 'bad') | Out-Null
        Set-Content -Path (Join-Path $root 'bad/app.yaml') -Value "name: x`nsurprise: true"
        New-Item -ItemType Directory -Path (Join-Path $root 'empty') | Out-Null
        $findings = @(Test-SafAppCatalog -Path $root)
        @($findings | Where-Object { $_.App -eq 'bad' -and $_.Check -eq 'schema' }).Count | Should -BeGreaterThan 1
        @($findings | Where-Object { $_.App -eq 'empty' -and $_.Check -eq 'manifest' }).Count | Should -Be 1
        @($findings | Where-Object { $_.App -eq 'good' -and $_.Severity -eq 'Error' }).Count | Should -Be 0
    }

    It 'warns about a URL without the version, a missing thumbprint, a fixed drive letter, and a duplicate URL' {
        $root = Join-Path $TestDrive 'warn'
        New-TestApp -Root $root -Id 'one' -Overrides @{
            Url = 'https://downloads.example.org/tool/latest/tool-x64.exe'
            SignatureSubject = 'Example Publisher'
            DetectionPath = 'C:\Tools\tool.exe'
        } | Out-Null
        New-TestApp -Root $root -Id 'two' -Overrides @{ Url = 'https://downloads.example.org/tool/latest/tool-x64.exe' } | Out-Null
        $warnings = @(Test-SafAppCatalog -Path $root | Where-Object Severity -eq 'Warning')
        ($warnings | Where-Object App -eq 'one').Check | Sort-Object | Should -Be @('path', 'signature', 'version')
        ($warnings | Where-Object App -eq 'two').Check | Sort-Object | Should -Be @('duplicate', 'version')
    }

    It 'rejects a folder name the packaging script cannot select' {
        $root = Join-Path $TestDrive 'ids'
        New-TestApp -Root $root -Id 'tool' | Out-Null
        Rename-Item (Join-Path $root 'tool') 'Tool'
        @(Test-SafAppCatalog -Path $root | Where-Object Check -eq 'id').Count | Should -Be 1
    }

    It 'renders Markdown with counts and escaped pipes' {
        $finding = [pscustomobject]@{ App = 'a'; Severity = 'Error'; Check = 'pin'; Message = 'x | y' }
        $md = $finding | ConvertTo-SafCatalogMarkdown -Apps @('a', 'b')
        $md | Should -Match '2 apps, 1 errors, 0 warnings'
        $md | Should -Match 'x \\\| y'
    }

    It 'scripts/Test-Apps.ps1 exits 0 for the shipped apps and 1 for a broken catalog' {
        $script = Join-Path $PSScriptRoot '../scripts/Test-Apps.ps1'
        $summary = Join-Path $TestDrive 'summary.md'
        & pwsh -NoLogo -NoProfile -File $script -SummaryPath $summary | Out-Null
        $LASTEXITCODE | Should -Be 0
        Get-Content -Raw $summary | Should -Match 'catalog check'

        $root = Join-Path $TestDrive 'broken'
        New-Item -ItemType Directory -Path (Join-Path $root 'bad') -Force | Out-Null
        Set-Content -Path (Join-Path $root 'bad/app.yaml') -Value 'name: only'
        & pwsh -NoLogo -NoProfile -File $script -Path $root | Out-Null
        $LASTEXITCODE | Should -Be 1
    }
}

Describe 'New-SafAppManifest' {
    It 'writes a manifest that Read-SafManifest accepts and a matching lock' {
        $root = Join-Path $TestDrive 'new'
        $result = New-TestApp -Root $root -Id 'tool' -Overrides @{ SignatureSubject = 'Example "Quoted" Publisher'; SignatureThumbprint = ('c' * 40) }
        $module = Get-Module SecureAppFactory
        $manifest = & $module { param($p) Read-SafManifest -Path $p } $result.ManifestPath
        $manifest.trust.signature.subjectContains | Should -Be 'Example "Quoted" Publisher'
        $manifest.trust.signature.thumbprint | Should -Be ('C' * 40)
        $manifest.uninstall.filePath | Should -Be '{ProgramFiles}\Example Tool\uninstall.exe'
        $manifest.source.fileName | Should -Be 'tool-1.2.3-x64.exe'
        (Get-Content -Raw $result.LockPath | ConvertFrom-Json).value | Should -Be $script:Hash
        @(Test-SafAppCatalog -Path $root | Where-Object Severity -in 'Error', 'Warning').Count | Should -Be 0
    }

    It 'hashes a local installer instead of taking -Sha256' {
        $file = Join-Path $TestDrive 'tool-1.2.3-x64.exe'
        Set-Content -LiteralPath $file -Value 'fixture bytes' -NoNewline
        $expected = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        $p = @{
            Id = 'local'; Name = 'Local'; Version = '1.2.3'; Publisher = 'P'
            Url = 'https://downloads.example.org/tool-1.2.3-x64.exe'; InstallerPath = $file
            InstallArguments = ''; UninstallPath = '{ProgramFiles}\L\u.exe'; DetectionPath = '{ProgramFiles}\L\l.exe'
            AppsPath = (Join-Path $TestDrive 'local')
        }
        (New-SafAppManifest @p).Sha256 | Should -Be $expected
    }

    It 'refuses to overwrite without -Force and honors -WhatIf' {
        $root = Join-Path $TestDrive 'force'
        New-TestApp -Root $root -Id 'tool' | Out-Null
        { New-TestApp -Root $root -Id 'tool' } | Should -Throw '*-Force*'
        { New-TestApp -Root $root -Id 'tool' -Overrides @{ Force = $true; Version = '1.2.4'; Url = 'https://downloads.example.org/tool-1.2.4.exe' } } | Should -Not -Throw
        Get-Content -Raw (Join-Path $root 'tool/app.yaml') | Should -Match '1.2.4'

        $dry = Join-Path $TestDrive 'dry'
        New-TestApp -Root $dry -Id 'tool' -Overrides @{ WhatIf = $true } | Out-Null
        Test-Path (Join-Path $dry 'tool/app.yaml') | Should -BeFalse
    }

    It 'rejects <Label>' -ForEach @(
        @{ Label = 'an http URL'; Overrides = @{ Url = 'http://downloads.example.org/t-1.2.3.exe' }; Message = '*https*' }
        @{ Label = 'a URL with credentials'; Overrides = @{ Url = 'https://user:pw@downloads.example.org/t-1.2.3.exe' }; Message = '*https*' }
        @{ Label = 'a thumbprint without a subject'; Overrides = @{ SignatureThumbprint = ('d' * 40) }; Message = '*SignatureSubject*' }
        @{ Label = 'a registry rule without a value name'; Overrides = @{ DetectionType = 'registry'; DetectionPath = 'HKLM\SOFTWARE\Example' }; Message = '*DetectionName*' }
        @{ Label = 'a file name with a path'; Overrides = @{ FileName = '..\evil.exe' }; Message = '*FileName*' }
    ) {
        { New-TestApp -Root (Join-Path $TestDrive 'reject') -Id 'tool' -Overrides $Overrides } | Should -Throw $Message
    }

    It 'rejects an id with uppercase letters and a short hash at parameter binding' {
        { New-TestApp -Root $TestDrive -Id 'Tool' } | Should -Throw '*lowercase*'
        { New-TestApp -Root $TestDrive -Id 'tool' -Overrides @{ Sha256 = 'abc' } } | Should -Throw
    }
}
