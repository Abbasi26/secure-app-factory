# Schema checks for apps/<name>/app.yaml. Unknown fields fail closed so a typo cannot skip a control.

function Add-SafSchemaError {
    param($Errors, [string]$Message)
    $Errors.Add($Message)
}

function Test-SafKnownKeys {
    param(
        $Object,
        [string[]]$Allowed,
        [string]$Path,
        $Errors
    )

    if ($null -eq $Object) { return }
    foreach ($name in @($Object.PSObject.Properties.Name)) {
        if ($Allowed -notcontains $name) {
            Add-SafSchemaError -Errors $Errors -Message "Unknown field '$Path.$name'."
        }
    }
}

function Test-SafNonEmptyString {
    param($Errors, $Object, [string]$Name, [string]$Path)
    $value = Get-SafProp -Object $Object -Name @($Name)
    if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
        Add-SafSchemaError -Errors $Errors -Message "$Path.$Name must be a non-empty string."
        return $false
    }
    return $true
}

function Test-SafManifestSchema {
    param(
        [Parameter(Mandatory = $true)]
        $Manifest
    )

    $errors = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Manifest) {
        Add-SafSchemaError -Errors $errors -Message 'Manifest is empty.'
        return ,$errors.ToArray()
    }

    Test-SafKnownKeys -Object $Manifest -Allowed @(
        'name', 'version', 'publisher', 'architecture', 'description', 'license',
        'informationUrl', 'source', 'trust', 'install', 'uninstall', 'detection', 'psadt'
    ) -Path 'manifest' -Errors $errors

    foreach ($field in @('name', 'version', 'publisher')) {
        Test-SafNonEmptyString -Errors $errors -Object $Manifest -Name $field -Path 'manifest' | Out-Null
    }

    $architecture = [string](Get-SafProp -Object $Manifest -Name @('architecture'))
    if (@('x86', 'x64', 'arm64') -notcontains $architecture) {
        Add-SafSchemaError -Errors $errors -Message "manifest.architecture must be x86, x64, or arm64."
    }

    $description = Get-SafProp -Object $Manifest -Name @('description')
    if ($null -ne $description -and $description -isnot [string]) {
        Add-SafSchemaError -Errors $errors -Message 'manifest.description must be a string.'
    }

    $license = Get-SafProp -Object $Manifest -Name @('license')
    if ($null -ne $license) {
        if ($license -isnot [string] -or $license -notmatch '^[A-Za-z0-9.+-]+$') {
            Add-SafSchemaError -Errors $errors -Message 'manifest.license must be an SPDX-style token.'
        }
    }

    $informationUrl = Get-SafProp -Object $Manifest -Name @('informationUrl')
    if ($null -ne $informationUrl -and -not (Test-SafHttpsUrl ([string]$informationUrl))) {
        Add-SafSchemaError -Errors $errors -Message 'manifest.informationUrl must be an https URL without embedded credentials.'
    }

    $source = Get-SafProp -Object $Manifest -Name @('source')
    if ($null -eq $source) {
        Add-SafSchemaError -Errors $errors -Message 'manifest.source is required.'
    }
    else {
        Test-SafKnownKeys -Object $source -Allowed @('type', 'url', 'fileName', 'application', 'architecture', 'installerType') -Path 'source' -Errors $errors
        $sourceType = [string](Get-SafProp -Object $source -Name @('type'))
        if (@('url', 'evergreen') -notcontains $sourceType) {
            Add-SafSchemaError -Errors $errors -Message "source.type must be 'url' or 'evergreen'."
        }
        $fileName = [string](Get-SafProp -Object $source -Name @('fileName'))
        if ($fileName -notmatch '^[A-Za-z0-9._+-]+$') {
            Add-SafSchemaError -Errors $errors -Message 'source.fileName must be a file name without a path.'
        }
        if ($sourceType -eq 'url') {
            $url = [string](Get-SafProp -Object $source -Name @('url'))
            if (-not (Test-SafHttpsUrl $url)) {
                Add-SafSchemaError -Errors $errors -Message 'source.url must be an https URL without embedded credentials.'
            }
        }
        if ($sourceType -eq 'evergreen') {
            $application = [string](Get-SafProp -Object $source -Name @('application'))
            if ($application -notmatch '^[A-Za-z0-9._+-]+$') {
                Add-SafSchemaError -Errors $errors -Message 'source.application is required for an Evergreen source.'
            }
        }
        foreach ($optional in @('architecture', 'installerType')) {
            $optionalValue = Get-SafProp -Object $source -Name @($optional)
            if ($null -ne $optionalValue -and ([string]$optionalValue -notmatch '^[A-Za-z0-9._+-]+$')) {
                Add-SafSchemaError -Errors $errors -Message "source.$optional must be a simple token."
            }
        }
    }

    $trust = Get-SafProp -Object $Manifest -Name @('trust')
    if ($null -eq $trust) {
        Add-SafSchemaError -Errors $errors -Message 'manifest.trust is required.'
    }
    else {
        Test-SafKnownKeys -Object $trust -Allowed @('algorithm', 'value', 'signature') -Path 'trust' -Errors $errors
        $algorithm = [string](Get-SafProp -Object $trust -Name @('algorithm'))
        if ($algorithm -ne 'SHA256') {
            Add-SafSchemaError -Errors $errors -Message "trust.algorithm must be SHA256."
        }
        if (Test-SafHasProp -Object $trust -Name 'value') {
            $hashValue = Get-SafProp -Object $trust -Name @('value')
            if ($null -ne $hashValue -and ([string]$hashValue -notmatch '^[A-Fa-f0-9]{64}$')) {
                Add-SafSchemaError -Errors $errors -Message 'trust.value must be 64 hexadecimal characters when it is set.'
            }
        }
        $signature = Get-SafProp -Object $trust -Name @('signature')
        if ($null -eq $signature) {
            Add-SafSchemaError -Errors $errors -Message 'trust.signature is required.'
        }
        else {
            Test-SafKnownKeys -Object $signature -Allowed @('required', 'subjectContains', 'thumbprint') -Path 'trust.signature' -Errors $errors
            $required = Get-SafProp -Object $signature -Name @('required')
            if ($required -isnot [bool]) {
                Add-SafSchemaError -Errors $errors -Message 'trust.signature.required must be true or false.'
            }
            $subject = Get-SafProp -Object $signature -Name @('subjectContains')
            if ($required -eq $true -and ($subject -isnot [string] -or [string]::IsNullOrWhiteSpace($subject))) {
                Add-SafSchemaError -Errors $errors -Message 'trust.signature.subjectContains is required when signature.required is true.'
            }
            $thumbprint = Get-SafProp -Object $signature -Name @('thumbprint')
            if ($null -ne $thumbprint -and [string]$thumbprint -ne '') {
                if ([string]$thumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
                    Add-SafSchemaError -Errors $errors -Message 'trust.signature.thumbprint must be 40 hexadecimal characters.'
                }
                if ($required -ne $true) {
                    Add-SafSchemaError -Errors $errors -Message 'trust.signature.thumbprint requires signature.required to be true.'
                }
            }
        }
    }

    foreach ($section in @('install', 'uninstall')) {
        $node = Get-SafProp -Object $Manifest -Name @($section)
        if ($null -eq $node) {
            Add-SafSchemaError -Errors $errors -Message "manifest.$section is required."
            continue
        }
    }
    $install = Get-SafProp -Object $Manifest -Name @('install')
    if ($null -ne $install) {
        Test-SafKnownKeys -Object $install -Allowed @('arguments') -Path 'install' -Errors $errors
        if (-not (Test-SafHasProp -Object $install -Name 'arguments') -or (Get-SafProp -Object $install -Name @('arguments')) -isnot [string]) {
            Add-SafSchemaError -Errors $errors -Message 'install.arguments must be a string. Use "" when the installer takes no arguments.'
        }
    }
    $uninstall = Get-SafProp -Object $Manifest -Name @('uninstall')
    if ($null -ne $uninstall) {
        Test-SafKnownKeys -Object $uninstall -Allowed @('filePath', 'arguments') -Path 'uninstall' -Errors $errors
        Test-SafNonEmptyString -Errors $errors -Object $uninstall -Name 'filePath' -Path 'uninstall' | Out-Null
        if (-not (Test-SafHasProp -Object $uninstall -Name 'arguments') -or (Get-SafProp -Object $uninstall -Name @('arguments')) -isnot [string]) {
            Add-SafSchemaError -Errors $errors -Message 'uninstall.arguments must be a string. Use "" when the uninstaller takes no arguments.'
        }
    }

    $detection = Get-SafProp -Object $Manifest -Name @('detection')
    if ($null -eq $detection) {
        Add-SafSchemaError -Errors $errors -Message 'manifest.detection is required.'
    }
    else {
        Test-SafKnownKeys -Object $detection -Allowed @('type', 'path', 'name', 'value') -Path 'detection' -Errors $errors
        $detectionType = [string](Get-SafProp -Object $detection -Name @('type'))
        if (@('file', 'registry') -notcontains $detectionType) {
            Add-SafSchemaError -Errors $errors -Message "detection.type must be 'file' or 'registry'."
        }
        Test-SafNonEmptyString -Errors $errors -Object $detection -Name 'path' -Path 'detection' | Out-Null
        if ($detectionType -eq 'registry') {
            Test-SafNonEmptyString -Errors $errors -Object $detection -Name 'name' -Path 'detection' | Out-Null
        }
    }

    $psadt = Get-SafProp -Object $Manifest -Name @('psadt')
    if ($null -ne $psadt) {
        Test-SafKnownKeys -Object $psadt -Allowed @(
            'appVendor', 'appName', 'appLang', 'appRevision', 'processesToClose', 'successExitCodes', 'rebootExitCodes'
        ) -Path 'psadt' -Errors $errors
        $processes = Get-SafProp -Object $psadt -Name @('processesToClose')
        if ($null -ne $processes) {
            foreach ($process in @($processes)) {
                if ($null -eq $process) {
                    Add-SafSchemaError -Errors $errors -Message 'psadt.processesToClose entries must be maps.'
                    continue
                }
                Test-SafKnownKeys -Object $process -Allowed @('name', 'description') -Path 'psadt.processesToClose' -Errors $errors
                $processName = [string](Get-SafProp -Object $process -Name @('name'))
                if ($processName -notmatch '^[A-Za-z0-9._+-]+$') {
                    Add-SafSchemaError -Errors $errors -Message 'psadt.processesToClose.name must be a process name.'
                }
            }
        }
        foreach ($codeField in @('successExitCodes', 'rebootExitCodes')) {
            $codes = Get-SafProp -Object $psadt -Name @($codeField)
            if ($null -eq $codes) { continue }
            foreach ($code in @($codes)) {
                if ($code -isnot [int] -and $code -isnot [long] -and $code -isnot [int64]) {
                    Add-SafSchemaError -Errors $errors -Message "psadt.$codeField must be a list of integers."
                }
            }
        }
    }

    return ,$errors.ToArray()
}

function Read-SafManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Manifest not found: $Path"
    }
    $text = [System.IO.File]::ReadAllText($Path)
    $parsed = ConvertTo-SafData -Node (ConvertFrom-SafYaml -Yaml $text)
    $schemaErrors = Test-SafManifestSchema -Manifest $parsed
    if ($schemaErrors -isnot [System.Array]) {
        if ($null -eq $schemaErrors) { $schemaErrors = @() }
        else { $schemaErrors = @($schemaErrors) }
    }
    if ($schemaErrors.Count -gt 0) {
        throw ("Manifest schema failed for {0}:`n - {1}" -f $Path, ($schemaErrors -join "`n - "))
    }
    return $parsed
}

function Read-SafLock {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    $lock = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    $algorithm = [string](Get-SafProp -Object $lock -Name @('algorithm'))
    $value = [string](Get-SafProp -Object $lock -Name @('value'))
    if ($algorithm -ne 'SHA256' -or $value -notmatch '^[A-Fa-f0-9]{64}$') {
        throw "Lock file must contain algorithm SHA256 and a 64-character value: $Path"
    }
    return $lock
}

function Write-SafLock {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Hash,
        [string]$Source
    )

    if (Test-Path -LiteralPath $Path) {
        throw "Refusing to overwrite an existing lock file: $Path"
    }
    $body = [ordered]@{
        algorithm  = 'SHA256'
        value      = $Hash.ToLowerInvariant()
        source     = $Source
        recordedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        recordedBy = 'trust-on-first-use'
    }
    Write-SafJsonFile -Path $Path -Value $body
}
