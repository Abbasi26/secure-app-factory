BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/SecureAppFactory/SecureAppFactory.psd1') -Force
    $script:ScriptPath = Join-Path $PSScriptRoot '../scripts/Test-PythonStartupHooks.ps1'

    function New-PthFile {
        param([string]$Folder, [string]$Name, [string[]]$Lines, [switch]$Bom)
        if (-not (Test-Path -LiteralPath $Folder)) { New-Item -ItemType Directory -Path $Folder | Out-Null }
        $file = Join-Path $Folder $Name
        $encoding = New-Object System.Text.UTF8Encoding($Bom.IsPresent)
        [System.IO.File]::WriteAllText($file, (($Lines -join "`n") + "`n"), $encoding)
        $file
    }
}

Describe 'Test-PythonStartupHook' {
    BeforeEach {
        $site = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $site | Out-Null
    }

    It 'reports <Name> as Malicious whatever its content' -ForEach @(
        @{ Name = 'agent_framework_meta.pth'; Version = '1.26.1' }
        @{ Name = 'af_runtime_diag.pth'; Version = '1.26.2' }
    ) {
        New-PthFile -Folder $site -Name $Name -Lines @('import example_module') | Out-Null
        $result = Test-PythonStartupHook -Path $site
        $result.Status | Should -Be 'Malicious'
        $result.Reason | Should -Match ([regex]::Escape($Version))
        $result.Reason | Should -Match 'MAL-2026-20101'
    }

    It 'keeps a known malicious name Malicious even with -AllowFile' {
        New-PthFile -Folder $site -Name 'af_runtime_diag.pth' -Lines @('import af_runtime_diag') | Out-Null
        (Test-PythonStartupHook -Path $site -AllowFile 'af_runtime_diag.pth').Status | Should -Be 'Malicious'
    }

    It 'reports an unknown import line as Suspicious with its line number' {
        New-PthFile -Folder $site -Name 'example_hook.pth' -Lines @('# comment', 'lib/example', 'import example_hook; example_hook.run()') | Out-Null
        $result = Test-PythonStartupHook -Path $site
        $result.Status | Should -Be 'Suspicious'
        @($result.ExecutableLines).Count | Should -Be 1
        $result.ExecutableLines[0].LineNumber | Should -Be 3
        $result.ExecutableLines[0].AllowedBy | Should -BeNullOrEmpty
    }

    It 'treats "import<TAB>" as executable, like CPython' {
        New-PthFile -Folder $site -Name 'tab.pth' -Lines @("import`texample") | Out-Null
        (Test-PythonStartupHook -Path $site).Status | Should -Be 'Suspicious'
    }

    It 'treats a line with leading spaces or a different word as a path, like CPython' {
        New-PthFile -Folder $site -Name 'paths.pth' -Lines @('  import example', 'importer', '#import example', '', 'src') | Out-Null
        (Test-PythonStartupHook -Path $site).Status | Should -Be 'PathsOnly'
    }

    It 'reads a UTF-8 BOM file the way CPython does' {
        New-PthFile -Folder $site -Name 'bom.pth' -Lines @('import example') -Bom | Out-Null
        (Test-PythonStartupHook -Path $site).Status | Should -Be 'Suspicious'
    }

    It 'allows the exact line written by <Source>' -ForEach @(
        @{ Source = 'setuptools'; Name = 'distutils-precedence.pth'; Line = "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); " }
        @{ Source = 'virtualenv'; Name = '_virtualenv.pth'; Line = 'import _virtualenv' }
        @{ Source = 'setuptools editable install'; Name = '__editable__.example_pkg-1.0.0.pth'; Line = "import __editable___example_pkg_1_0_0_finder; __editable___example_pkg_1_0_0_finder.install()" }
        @{ Source = 'pywin32'; Name = 'pywin32.pth'; Line = 'import pywin32_bootstrap' }
    ) {
        New-PthFile -Folder $site -Name $Name -Lines @($Line) | Out-Null
        $result = Test-PythonStartupHook -Path $site
        $result.Status | Should -Be 'Allowed'
        $result.Reason | Should -Match ([regex]::Escape($Source))
    }

    It 'does not allow a known file name with extra code' {
        New-PthFile -Folder $site -Name '_virtualenv.pth' -Lines @('import _virtualenv; import example_hook') | Out-Null
        (Test-PythonStartupHook -Path $site).Status | Should -Be 'Suspicious'
    }

    It 'does not allow a known line under a different file name' {
        New-PthFile -Folder $site -Name 'zz_virtualenv.pth' -Lines @('import _virtualenv') | Out-Null
        (Test-PythonStartupHook -Path $site).Status | Should -Be 'Suspicious'
    }

    It 'downgrades a reviewed file name passed to -AllowFile' {
        New-PthFile -Folder $site -Name 'example-nspkg.pth' -Lines @('import sys, types, os') | Out-Null
        (Test-PythonStartupHook -Path $site -AllowFile 'example-nspkg.pth').Status | Should -Be 'Allowed'
    }

    It 'shortens long executable lines to 120 characters' {
        New-PthFile -Folder $site -Name 'long.pth' -Lines @('import x; ' + ('a' * 300)) | Out-Null
        (Test-PythonStartupHook -Path $site).ExecutableLines[0].Text.Length | Should -Be 123
    }

    It 'looks in subfolders only with -Recurse' {
        New-PthFile -Folder (Join-Path $site 'pkg/data') -Name 'nested.pth' -Lines @('import nested') | Out-Null
        @(Test-PythonStartupHook -Path $site).Count | Should -Be 0
        (Test-PythonStartupHook -Path $site -Recurse).Status | Should -Be 'Suspicious'
    }

    It 'accepts a single .pth file and ignores other files' {
        $file = New-PthFile -Folder $site -Name 'single.pth' -Lines @('src')
        New-PthFile -Folder $site -Name 'notes.txt' -Lines @('import example') | Out-Null
        (Test-PythonStartupHook -Path $file).Status | Should -Be 'PathsOnly'
        @(Test-PythonStartupHook -Path $site).Count | Should -Be 1
    }

    It 'throws on a missing path' {
        { Test-PythonStartupHook -Path (Join-Path $site 'missing') } | Should -Throw '*Path not found*'
    }
}

Describe 'scripts/Test-PythonStartupHooks.ps1' {
    BeforeEach {
        $site = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $site | Out-Null
        $exe = (Get-Process -Id $PID).Path
    }

    It 'exits 0 when only allowed or path-only files exist' {
        New-PthFile -Folder $site -Name '_virtualenv.pth' -Lines @('import _virtualenv') | Out-Null
        New-PthFile -Folder $site -Name 'paths.pth' -Lines @('src') | Out-Null
        & $exe -NoProfile -NonInteractive -File $script:ScriptPath -Path $site | Out-Null
        $LASTEXITCODE | Should -Be 0
    }

    It 'exits 1 on a malicious file and writes a summary' {
        New-PthFile -Folder $site -Name 'agent_framework_meta.pth' -Lines @('import agent_framework_meta') | Out-Null
        $summary = Join-Path $site 'summary.md'
        & $exe -NoProfile -NonInteractive -File $script:ScriptPath -Path $site -SummaryPath $summary | Out-Null
        $LASTEXITCODE | Should -Be 1
        Get-Content -Raw -LiteralPath $summary | Should -Match 'Malicious'
    }
}
