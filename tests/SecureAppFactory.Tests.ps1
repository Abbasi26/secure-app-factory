BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:ModuleManifest = Join-Path $script:RepoRoot 'src/SecureAppFactory/SecureAppFactory.psd1'
    Import-Module $script:ModuleManifest -Force
}

Describe 'YAML schema' {
    It 'reads nested maps and lists from the 7-Zip manifest' {
        $manifest = InModuleScope SecureAppFactory -Parameters @{ ManifestPath = (Join-Path $script:RepoRoot 'apps/7zip/app.yaml') } {
            param($ManifestPath)
            Read-SafManifest -Path $ManifestPath
        }
        $manifest.name | Should -Be '7-Zip'
        $manifest.trust.signature.required | Should -BeFalse
        $manifest.psadt.processesToClose.Count | Should -Be 2
        $manifest.psadt.processesToClose[0].name | Should -Be '7zFM'
        $manifest.psadt.successExitCodes[0] | Should -Be 0
        $manifest.uninstall.filePath | Should -Be '{ProgramFiles}\7-Zip\Uninstall.exe'
    }

    It 'requires a signature subject and thumbprint policy for Notepad++' {
        $manifest = InModuleScope SecureAppFactory -Parameters @{ ManifestPath = (Join-Path $script:RepoRoot 'apps/notepadpp/app.yaml') } {
            param($ManifestPath)
            Read-SafManifest -Path $ManifestPath
        }
        $manifest.trust.signature.required | Should -BeTrue
        $manifest.trust.signature.subjectContains | Should -Be 'NOTEPAD++'
        $manifest.trust.signature.thumbprint | Should -Be '1E8E0D13B608BA908572C1A129FAEC5D228DF8A2'
        $manifest.trust.value | Should -Match '^[a-f0-9]{64}$'
    }

    It 'rejects an http download URL' {
        $errors = InModuleScope SecureAppFactory {
            $yaml = @"
name: Demo
version: "1.0"
publisher: Demo
architecture: x64
source:
  type: url
  url: http://example.invalid/setup.exe
  fileName: setup.exe
trust:
  algorithm: SHA256
  value: d54bf805f9f3704d1e8db2fa3498ae7ef2df0312b40b558e7c71c734430a665d
  signature:
    required: false
install:
  arguments: /S
uninstall:
  filePath: "{ProgramFiles}\\Demo\\uninstall.exe"
  arguments: /S
detection:
  type: file
  path: "{ProgramFiles}\\Demo\\demo.exe"
"@
            $data = ConvertTo-SafData -Node (ConvertFrom-SafYaml -Yaml $yaml)
            @(Test-SafManifestSchema -Manifest $data)
        }
        $errors -join ' ' | Should -Match 'https'
    }

    It 'rejects a required signature without a subject' {
        $errors = InModuleScope SecureAppFactory {
            $yaml = @"
name: Demo
version: "1.0"
publisher: Demo
architecture: x64
source:
  type: url
  url: https://example.invalid/setup.exe
  fileName: setup.exe
trust:
  algorithm: SHA256
  signature:
    required: true
install:
  arguments: ""
uninstall:
  filePath: "{ProgramFiles}\\Demo\\uninstall.exe"
  arguments: ""
detection:
  type: file
  path: "{ProgramFiles}\\Demo\\demo.exe"
"@
            $data = ConvertTo-SafData -Node (ConvertFrom-SafYaml -Yaml $yaml)
            @(Test-SafManifestSchema -Manifest $data)
        }
        $errors -join ' ' | Should -Match 'subjectContains'
    }

    It 'rejects an unknown field' {
        $errors = InModuleScope SecureAppFactory {
            $yaml = @"
name: Demo
version: "1.0"
publisher: Demo
architecture: x64
ownerEmail: hidden
source:
  type: url
  url: https://example.invalid/setup.exe
  fileName: setup.exe
trust:
  algorithm: SHA256
  signature:
    required: false
install:
  arguments: /S
uninstall:
  filePath: "{ProgramFiles}\\Demo\\uninstall.exe"
  arguments: /S
detection:
  type: file
  path: "{ProgramFiles}\\Demo\\demo.exe"
"@
            $data = ConvertTo-SafData -Node (ConvertFrom-SafYaml -Yaml $yaml)
            @(Test-SafManifestSchema -Manifest $data)
        }
        $errors -join ' ' | Should -Match 'Unknown field'
    }

    It 'rejects tabs and duplicate keys' {
        { InModuleScope SecureAppFactory { ConvertFrom-SafYaml -Yaml "name:`tDemo" } } | Should -Throw '*Tabs*'
        { InModuleScope SecureAppFactory { ConvertFrom-SafYaml -Yaml "name: Demo`nname: Other" } } | Should -Throw '*Duplicate*'
    }
}

Describe 'Installer trust' {
    BeforeAll {
        function New-TrustManifest {
            param(
                [bool]$Required = $false,
                [string]$Subject = '',
                [string]$Thumbprint = '',
                [string]$Hash = ''
            )
            $yaml = @"
name: Demo
version: "1.0"
publisher: Demo Publisher
architecture: x64
source:
  type: url
  url: https://example.invalid/setup.exe
  fileName: setup.exe
trust:
  algorithm: SHA256
  signature:
    required: $($Required.ToString().ToLowerInvariant())
"@
            if ($Subject) { $yaml += "`n    subjectContains: $Subject" }
            if ($Thumbprint) { $yaml += "`n    thumbprint: $Thumbprint" }
            if ($Hash) { $yaml += "`n  value: $Hash" }
            $yaml += @"

install:
  arguments: /S
uninstall:
  filePath: "{ProgramFiles}\\Demo\\uninstall.exe"
  arguments: /S
detection:
  type: file
  path: "{ProgramFiles}\\Demo\\demo.exe"
"@
            return InModuleScope SecureAppFactory -Parameters @{ Yaml = $yaml } {
                param($Yaml)
                ConvertTo-SafData -Node (ConvertFrom-SafYaml -Yaml $Yaml)
            }
        }
    }

    It 'passes a matching hash and an allowed unsigned file' {
        $file = Join-Path $TestDrive 'unsigned.bin'
        Set-Content -LiteralPath $file -Value 'unsigned' -NoNewline
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
        $manifest = New-TrustManifest -Hash $hash
        $result = Test-InstallerTrust -Path $file -Manifest $manifest -SignatureInspector {
            param($Path)
            [pscustomobject]@{ Status = 'NotSigned'; Subject = ''; Thumbprint = ''; Platform = 'Test' }
        }
        $result.Passed | Should -BeTrue
        $result.Hash.Match | Should -BeTrue
    }

    It 'fails a hash mismatch and does not overwrite the lock' {
        $file = Join-Path $TestDrive 'mismatch.bin'
        Set-Content -LiteralPath $file -Value 'one' -NoNewline
        $lock = Join-Path $TestDrive 'lock.json'
        $manifest = New-TrustManifest -Hash ('a' * 64)
        $before = $null
        $result = Test-InstallerTrust -Path $file -Manifest $manifest -LockPath $lock -TrustOnFirstUse -SignatureInspector {
            param($Path)
            [pscustomobject]@{ Status = 'NotSigned'; Subject = ''; Thumbprint = ''; Platform = 'Test' }
        }
        $result.Passed | Should -BeFalse
        $result.LockAction | Should -Be 'none'
        Test-Path -LiteralPath $lock | Should -BeFalse
        $result.Reasons -join ' ' | Should -Match 'does not match'
    }

    It 'previews trust on first use without writing a lock' {
        $file = Join-Path $TestDrive 'new.bin'
        Set-Content -LiteralPath $file -Value 'fresh' -NoNewline
        $lock = Join-Path $TestDrive 'fresh-lock.json'
        $manifest = New-TrustManifest
        $result = Test-InstallerTrust -Path $file -Manifest $manifest -LockPath $lock -SignatureInspector {
            param($Path)
            [pscustomobject]@{ Status = 'NotSigned'; Subject = ''; Thumbprint = ''; Platform = 'Test' }
        }
        $result.Passed | Should -BeFalse
        $result.LockAction | Should -Be 'preview'
        Test-Path -LiteralPath $lock | Should -BeFalse
    }

    It 'writes a lock only when trust on first use is explicit' {
        $file = Join-Path $TestDrive 'tofu.bin'
        Set-Content -LiteralPath $file -Value 'record-me' -NoNewline
        $lock = Join-Path $TestDrive 'tofu-lock.json'
        $manifest = New-TrustManifest
        $result = Test-InstallerTrust -Path $file -Manifest $manifest -LockPath $lock -TrustOnFirstUse -SignatureInspector {
            param($Path)
            [pscustomobject]@{ Status = 'NotSigned'; Subject = ''; Thumbprint = ''; Platform = 'Test' }
        }
        $result.Passed | Should -BeTrue
        $result.LockAction | Should -Be 'written'
        $saved = Get-Content -Raw -LiteralPath $lock | ConvertFrom-Json
        $saved.value | Should -Be $result.Hash.Actual
        $saved.recordedBy | Should -Be 'trust-on-first-use'
    }

    It 'fails a required signature when the subject or thumbprint does not match' {
        $file = Join-Path $TestDrive 'signed.bin'
        Set-Content -LiteralPath $file -Value 'signed' -NoNewline
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
        $manifest = New-TrustManifest -Required $true -Subject 'NOTEPAD++' -Thumbprint ('AB' * 20) -Hash $hash
        $result = Test-InstallerTrust -Path $file -Manifest $manifest -SignatureInspector {
            param($Path)
            [pscustomobject]@{ Status = 'Valid'; Subject = 'CN=Other Vendor'; Thumbprint = ('CD' * 20); Platform = 'Test' }
        }
        $result.Passed | Should -BeFalse
        $result.Signature.Match | Should -BeFalse
    }

    It 'fails a broken signature even when a signature is not required' {
        $file = Join-Path $TestDrive 'broken.bin'
        Set-Content -LiteralPath $file -Value 'broken' -NoNewline
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
        $manifest = New-TrustManifest -Hash $hash
        $result = Test-InstallerTrust -Path $file -Manifest $manifest -SignatureInspector {
            param($Path)
            [pscustomobject]@{ Status = 'HashMismatch'; Subject = ''; Thumbprint = ''; Platform = 'Test' }
        }
        $result.Passed | Should -BeFalse
        $result.Reasons -join ' ' | Should -Match 'HashMismatch'
    }

    It 'fails closed when a required signature cannot be checked' {
        $file = Join-Path $TestDrive 'unknown.bin'
        Set-Content -LiteralPath $file -Value 'unknown' -NoNewline
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
        $manifest = New-TrustManifest -Required $true -Subject 'NOTEPAD++' -Hash $hash
        $result = Test-InstallerTrust -Path $file -Manifest $manifest -SignatureInspector {
            param($Path)
            [pscustomobject]@{ Status = 'Unavailable'; Subject = ''; Thumbprint = ''; Platform = 'NonWindows' }
        }
        $result.Passed | Should -BeFalse
    }
}

Describe 'Package pipeline' {
    It 'runs the offline demo for both example apps' {
        $root = Join-Path $TestDrive 'demo'
        $downloadLog = @{ Called = $false }
        foreach ($app in @('7zip', 'notepadpp')) {
            $result = Invoke-SafPipeline -ManifestPath (Join-Path $script:RepoRoot "apps/$app/app.yaml") -Destination (Join-Path $root $app) -Demo -WebClient { $downloadLog.Called = $true }.GetNewClosure()
            $result.Passed | Should -BeTrue
            $result.Upload.Status | Should -Be 'Disabled'
            $result.SmokeTest.Status | Should -Be 'Preview'
            $result.IntuneWin.Status | Should -Be 'Skipped'
            $result.Psadt.ToolkitBundled | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $root "$app/REPORT.md") | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $root "$app/sbom.cdx.json") | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $root "$app/provenance.json") | Should -BeTrue
        }
        $downloadLog.Called | Should -BeFalse
        $report = Get-Content -Raw -LiteralPath (Join-Path $root '7zip/REPORT.md')
        $report | Should -Match 'Demo mode'
        $report | Should -Match '7-Zip'
        $bom = Get-Content -Raw -LiteralPath (Join-Path $root 'notepadpp/sbom.cdx.json') | ConvertFrom-Json
        $bom.bomFormat | Should -Be 'CycloneDX'
        $bom.specVersion | Should -Be '1.6'
        $bom.components[0].hashes[0].content | Should -Be (Get-Content -Raw (Join-Path $script:RepoRoot 'demo/fixtures/notepadpp/installer.sha256')).Trim()
        $provenance = Get-Content -Raw -LiteralPath (Join-Path $root '7zip/provenance.json') | ConvertFrom-Json
        $provenance.schema | Should -Be 'secure-app-factory.provenance.v0.1'
        $provenance.note | Should -Match 'not a SLSA'
        $scriptText = Get-Content -Raw -LiteralPath (Join-Path $root '7zip/package/Invoke-AppDeployToolkit.ps1')
        $scriptText | Should -Match '7z2604-x64.exe'
        $scriptText | Should -Match '/S'
        $scriptText | Should -Match '\$env:ProgramFiles'
    }

    It 'stops before packaging when the mocked signature fails' {
        $destination = Join-Path $TestDrive 'bad-sig'
        { Invoke-SafPipeline -ManifestPath (Join-Path $script:RepoRoot 'apps/notepadpp/app.yaml') -Destination $destination -Demo -SignatureInspector {
            param($Path)
            [pscustomobject]@{ Status = 'Valid'; Subject = 'CN=Other Vendor'; Thumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; Platform = 'Demo' }
        } } | Should -Throw '*trust check failed*'
        Test-Path -LiteralPath (Join-Path $destination 'package') | Should -BeFalse
        $report = Get-Content -Raw -LiteralPath (Join-Path $destination 'REPORT.md')
        $report | Should -Match 'Fail'
    }

    It 'refuses demo mode combined with an upload' {
        { Invoke-SafPipeline -ManifestPath (Join-Path $script:RepoRoot 'apps/7zip/app.yaml') -Destination (Join-Path $TestDrive 'nope') -Demo -Upload } | Should -Throw '*Demo mode*'
    }
}

Describe 'Intune upload gate' {
    BeforeAll {
        $script:UploadManifest = InModuleScope SecureAppFactory -Parameters @{ ManifestPath = (Join-Path $script:RepoRoot 'apps/7zip/app.yaml') } {
            param($ManifestPath)
            Read-SafManifest -Path $ManifestPath
        }
        $script:IntuneWin = Join-Path $TestDrive 'sample.intunewin'
        $stage = Join-Path $TestDrive 'stage'
        $meta = Join-Path $stage 'IntuneWinPackage/Metadata'
        $content = Join-Path $stage 'IntuneWinPackage/Contents'
        New-Item -ItemType Directory -Path $meta, $content -Force | Out-Null
        $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<ApplicationInfo>
  <FileName>IntunePackage.intunewin</FileName>
  <UnencryptedContentSize>5</UnencryptedContentSize>
  <EncryptionInfo>
    <EncryptionKey>YQ==</EncryptionKey>
    <MacKey>YQ==</MacKey>
    <InitializationVector>YQ==</InitializationVector>
    <Mac>YQ==</Mac>
    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>
    <FileDigest>abc</FileDigest>
    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>
  </EncryptionInfo>
</ApplicationInfo>
'@
        [System.IO.File]::WriteAllText((Join-Path $meta 'Detection.xml'), $xml)
        [System.IO.File]::WriteAllText((Join-Path $content 'IntunePackage.intunewin'), 'hello')
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        if (Test-Path -LiteralPath $script:IntuneWin) { Remove-Item -LiteralPath $script:IntuneWin -Force }
        [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $script:IntuneWin)
    }

    It 'previews the upload and does not call Graph' {
        $log = @{ Calls = 0 }
        $result = Send-IntunePackage -Manifest $script:UploadManifest -IntuneWinPath $script:IntuneWin -HttpInvoker {
            param($Request)
            $log.Calls++
        }.GetNewClosure()
        $result.Status | Should -Be 'Disabled'
        $log.Calls | Should -Be 0
        $result.Plan.InstallCommandLine | Should -Match 'DeployMode Silent'
        $result.Plan.CreatesAssignment | Should -BeFalse
        ($result | ConvertTo-Json -Depth 8) | Should -Not -Match 'client_secret'
    }

    It 'skips when upload is requested without secrets' {
        $log = @{ Calls = 0 }
        $result = Send-IntunePackage -Manifest $script:UploadManifest -IntuneWinPath $script:IntuneWin -Upload -TenantId '' -ClientId '' -ClientSecret '' -HttpInvoker {
            param($Request)
            $log.Calls++
        }.GetNewClosure()
        $result.Status | Should -Be 'Skipped'
        $log.Calls | Should -Be 0
    }

    It 'uploads only the Graph sequence and keeps the secret out of the result' {
        $log = @{ Calls = (New-Object System.Collections.Generic.List[object]); Gets = 0 }
        $secret = 'super-secret-value'
        $invoker = {
            param($Request)
            $log.Calls.Add($Request)
            $uri = [string]$Request.Uri
            if ($uri -like '*/oauth2/v2.0/token') { return @{ access_token = 'token-value' } }
            if ($Request.Method -eq 'POST' -and $uri -match '/mobileApps$' ) { return @{ id = 'app-1' } }
            if ($Request.Method -eq 'POST' -and $uri -match '/contentVersions$') { return @{ id = '3' } }
            if ($Request.Method -eq 'POST' -and $uri -match '/files$') { return @{ id = 'file-1' } }
            if ($Request.Method -eq 'GET' -and $uri -match '/files/file-1$') {
                $log.Gets++
                if ($log.Gets -eq 1) {
                    return @{ uploadState = 'azureStorageUriRequestSuccess'; azureStorageUri = 'https://example.invalid/blob?sig=do-not-leak' }
                }
                return @{ uploadState = 'commitFileSuccess' }
            }
            return @{}
        }.GetNewClosure()

        $result = Send-IntunePackage -Manifest $script:UploadManifest -IntuneWinPath $script:IntuneWin -Upload -TenantId '00000000-0000-0000-0000-000000000000' -ClientId '11111111-1111-1111-1111-111111111111' -ClientSecret $secret -HttpInvoker $invoker -PollDelaySeconds 0
        $result.Status | Should -Be 'Uploaded'
        $result.AppId | Should -Be 'app-1'
        $result.Steps | Should -Contain 'upload-blocks'
        $result.Steps | Should -Contain 'patch-app'
        $rendered = $result | ConvertTo-Json -Depth 12
        $rendered | Should -Not -Match [regex]::Escape($secret)
        $rendered | Should -Not -Match 'do-not-leak'
        $tokenCall = $log.Calls | Where-Object { $_.Uri -like '*/oauth2/v2.0/token' } | Select-Object -First 1
        $tokenCall.Body.Contains($secret) | Should -BeTrue
    }
}

Describe 'Repository hygiene' {
    It 'keeps PowerShell files ASCII' {
        $files = Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -Include '*.ps1', '*.psm1', '*.psd1'
        foreach ($file in $files) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $high = @($bytes | Where-Object { $_ -gt 127 })
            $high.Count | Should -Be 0 -Because $file.FullName
        }
    }

    It 'pins external tools by sha256' {
        $tools = Get-Content -Raw -LiteralPath (Join-Path $script:RepoRoot 'src/SecureAppFactory/data/external-tools.json') | ConvertFrom-Json
        $tools.psadt.sha256 | Should -Match '^[a-f0-9]{64}$'
        $tools.intuneWinAppUtil.exeSha256 | Should -Match '^[a-f0-9]{64}$'
        $tools.psadt.url | Should -Match '^https://'
        $tools.intuneWinAppUtil.archiveUrl | Should -Match '^https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/'
    }

    It 'rejects a zip entry that escapes the destination' {
        $zip = Join-Path $TestDrive 'evil.zip'
        $dest = Join-Path $TestDrive 'zip-out'
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($zip, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            $entry = $archive.CreateEntry('../escaped.txt')
            $writer = New-Object System.IO.StreamWriter ($entry.Open())
            try { $writer.Write('nope') } finally { $writer.Dispose() }
        }
        finally { $archive.Dispose() }
        { InModuleScope SecureAppFactory -Parameters @{ ZipPath = $zip; Destination = $dest } { Expand-SafZip -ZipPath $ZipPath -Destination $Destination } } | Should -Throw '*escapes*'
        Test-Path -LiteralPath (Join-Path $TestDrive 'escaped.txt') | Should -BeFalse
    }
}
