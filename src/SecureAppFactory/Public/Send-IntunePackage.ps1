function Get-SafIntuneDetectionRule {
    param($Manifest)

    $type = [string]$Manifest.detection.type
    if ($type -eq 'file') {
        $full = Expand-SafIntunePath -Path ([string]$Manifest.detection.path)
        return [ordered]@{
            '@odata.type'          = '#microsoft.graph.win32LobAppFileSystemRule'
            ruleType               = 'detection'
            path                   = [string](Split-Path -Parent $full)
            fileOrFolderName       = [string](Split-Path -Leaf $full)
            check32BitOn64System   = $false
            operationType          = 'exists'
            operator               = 'notConfigured'
            comparisonValue        = $null
        }
    }

    $value = Get-SafProp -Object $Manifest -Name @('detection', 'value')
    $hasValue = -not [string]::IsNullOrWhiteSpace([string]$value)
    return [ordered]@{
        '@odata.type'        = '#microsoft.graph.win32LobAppRegistryRule'
        ruleType             = 'detection'
        keyPath              = ConvertTo-SafRegistryIntunePath -Path ([string]$Manifest.detection.path)
        valueName            = [string]$Manifest.detection.name
        operationType        = $(if ($hasValue) { 'string' } else { 'exists' })
        operator             = $(if ($hasValue) { 'equal' } else { 'notConfigured' })
        comparisonValue      = $(if ($hasValue) { [string]$value } else { $null })
        check32BitOn64System = $false
    }
}

function Get-IntuneUploadPlan {
    <#
    .SYNOPSIS
        Builds the Intune Win32 app body that would be uploaded. Does not call Graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Manifest,
        [string]$IntuneWinPath
    )

    $safeName = ([string]$Manifest.name -replace '[^A-Za-z0-9._+-]', '-')
    $fileName = "$safeName.intunewin"
    $present = $false
    $length = 0
    if (-not [string]::IsNullOrWhiteSpace($IntuneWinPath) -and (Test-Path -LiteralPath $IntuneWinPath)) {
        $present = $true
        $fileName = Split-Path -Leaf $IntuneWinPath
        $length = (Get-Item -LiteralPath $IntuneWinPath).Length
    }

    $description = [string](Get-SafProp -Object $Manifest -Name @('description'))
    if ([string]::IsNullOrWhiteSpace($description)) {
        $description = "Packaged by Secure App Factory $($script:SafVersion)."
    }
    $installCommand = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-AppDeployToolkit.ps1 -DeploymentType Install -DeployMode Silent'
    $uninstallCommand = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-AppDeployToolkit.ps1 -DeploymentType Uninstall -DeployMode Silent'
    $info = [string](Get-SafProp -Object $Manifest -Name @('informationUrl'))

    $body = [ordered]@{
        '@odata.type'                   = '#microsoft.graph.win32LobApp'
        displayName                     = [string]$Manifest.name
        description                     = $description
        publisher                       = [string]$Manifest.publisher
        displayVersion                  = [string]$Manifest.version
        fileName                        = $fileName
        setupFilePath                   = 'Invoke-AppDeployToolkit.ps1'
        installCommandLine              = $installCommand
        uninstallCommandLine            = $uninstallCommand
        allowedArchitectures            = [string]$Manifest.architecture
        minimumSupportedOperatingSystem = [ordered]@{ v10_1607 = $true }
        installExperience               = [ordered]@{
            '@odata.type'         = '#microsoft.graph.win32LobAppInstallExperience'
            runAsAccount          = 'system'
            deviceRestartBehavior = 'basedOnReturnCode'
        }
        returnCodes                     = @(
            [ordered]@{ returnCode = 0; type = 'success' },
            [ordered]@{ returnCode = 3010; type = 'softReboot' },
            [ordered]@{ returnCode = 1641; type = 'hardReboot' },
            [ordered]@{ returnCode = 1618; type = 'retry' }
        )
        rules                           = @(Get-SafIntuneDetectionRule -Manifest $Manifest)
        notes                           = "Packaged by Secure App Factory $($script:SafVersion). No assignment is created by v0.1."
    }
    if (-not [string]::IsNullOrWhiteSpace($info)) {
        $body.informationUrl = $info
    }

    return [pscustomobject]@{
        DisplayName        = [string]$Manifest.name
        Publisher          = [string]$Manifest.publisher
        Version            = [string]$Manifest.version
        InstallCommandLine = $installCommand
        UninstallCommandLine = $uninstallCommand
        IntuneWinPresent   = $present
        IntuneWinPath      = $(if ($present) { $IntuneWinPath } else { '' })
        IntuneWinBytes     = $length
        GraphBase          = 'https://graph.microsoft.com/beta'
        CreatesAssignment  = $false
        AppBody            = $body
    }
}

function Get-SafIntuneWinMetadata {
    param([Parameter(Mandatory = $true)][string]$Path)

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $meta = $zip.Entries | Where-Object { ($_.FullName -replace '\\', '/') -eq 'IntuneWinPackage/Metadata/Detection.xml' } | Select-Object -First 1
        if (-not $meta) {
            throw 'Detection.xml was not found inside the .intunewin file.'
        }
        $reader = New-Object System.IO.StreamReader ($meta.Open())
        try { $xmlText = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
        $xml = [xml]$xmlText
        $info = $xml.ApplicationInfo
        $innerName = [string]$info.FileName
        $content = @($zip.Entries | Where-Object { ($_.FullName -replace '\\', '/') -like 'IntuneWinPackage/Contents/*' -and -not [string]::IsNullOrWhiteSpace($_.Name) })
        $match = $content | Where-Object { $_.Name -eq $innerName } | Select-Object -First 1
        if (-not $match) { $match = $content | Select-Object -First 1 }
        if (-not $match) {
            throw 'Encrypted content was not found inside the .intunewin file.'
        }
        $stream = $match.Open()
        $memory = New-Object System.IO.MemoryStream
        try { $stream.CopyTo($memory) }
        finally { $stream.Dispose() }
        $bytes = $memory.ToArray()
        if ($bytes.Length -gt 524288000) {
            throw 'Refusing to load an encrypted payload larger than 500 MB into memory.'
        }
        $profile = [string]$info.EncryptionInfo.ProfileIdentifier
        if ([string]::IsNullOrWhiteSpace($profile)) { $profile = 'ProfileVersion1' }
        return [pscustomobject]@{
            FileName         = $innerName
            UnencryptedSize  = [int64]$info.UnencryptedContentSize
            EncryptedBytes   = $bytes
            Encryption       = [ordered]@{
                encryptionKey        = [string]$info.EncryptionInfo.EncryptionKey
                macKey               = [string]$info.EncryptionInfo.MacKey
                initializationVector = [string]$info.EncryptionInfo.InitializationVector
                mac                  = [string]$info.EncryptionInfo.Mac
                profileIdentifier    = $profile
                fileDigest           = [string]$info.EncryptionInfo.FileDigest
                fileDigestAlgorithm  = [string]$info.EncryptionInfo.FileDigestAlgorithm
            }
        }
    }
    finally {
        $zip.Dispose()
    }
}

function Invoke-SafDefaultHttp {
    param($Request)

    $params = @{
        Method          = $Request.Method
        Uri             = $Request.Uri
        UseBasicParsing = $true
    }
    if ($Request.Contains('Headers') -and $Request.Headers) {
        $params.Headers = $Request.Headers
    }
    if ($Request.Contains('BodyBytes') -and $null -ne $Request.BodyBytes) {
        $params.Body = $Request.BodyBytes
        if ($Request.ContentType) { $params.ContentType = $Request.ContentType }
        return Invoke-WebRequest @params
    }
    if ($Request.Contains('Body') -and $null -ne $Request.Body) {
        $params.Body = $Request.Body
        if ($Request.ContentType) { $params.ContentType = $Request.ContentType }
    }
    return Invoke-RestMethod @params
}

function Wait-SafFileState {
    param(
        [string]$Uri,
        [string]$Token,
        [string]$Desired,
        [string[]]$FailStates,
        [scriptblock]$Invoker,
        [int]$MaxAttempts,
        [int]$DelaySeconds
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $status = & $Invoker @{
            Method  = 'GET'
            Uri     = $Uri
            Headers = @{ Authorization = "Bearer $Token" }
        }
        $state = [string](Get-SafProp -Object $status -Name @('uploadState'))
        if ($state -eq $Desired) { return $status }
        if ($FailStates -contains $state) {
            throw "Intune file state '$state' while waiting for '$Desired'."
        }
        if ($DelaySeconds -gt 0 -and $attempt -lt $MaxAttempts) {
            Start-Sleep -Seconds $DelaySeconds
        }
    }
    throw "Timed out waiting for Intune file state '$Desired'."
}

function Send-SafBlobBlocks {
    param(
        [string]$SasUri,
        [byte[]]$Bytes,
        [scriptblock]$Invoker
    )

    $blockSize = 4MB
    $ids = New-Object System.Collections.Generic.List[string]
    $offset = 0
    $index = 0
    while ($offset -lt $Bytes.Length) {
        $count = [Math]::Min($blockSize, $Bytes.Length - $offset)
        $chunk = New-Object byte[] $count
        [System.Array]::Copy($Bytes, $offset, $chunk, 0, $count)
        $blockId = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($index.ToString('D8')))
        $ids.Add($blockId)
        $separator = '?'
        if ($SasUri.Contains('?')) { $separator = '&' }
        $blockUri = '{0}{1}comp=block&blockid={2}' -f $SasUri, $separator, [uri]::EscapeDataString($blockId)
        & $Invoker @{
            Method      = 'PUT'
            Uri         = $blockUri
            BodyBytes   = $chunk
            ContentType = 'application/octet-stream'
        } | Out-Null
        $offset += $count
        $index++
    }

    $xml = New-Object System.Text.StringBuilder
    [void]$xml.Append('<?xml version="1.0" encoding="utf-8"?><BlockList>')
    foreach ($id in $ids) {
        [void]$xml.Append('<Latest>')
        [void]$xml.Append([System.Security.SecurityElement]::Escape($id))
        [void]$xml.Append('</Latest>')
    }
    [void]$xml.Append('</BlockList>')
    $separator = '?'
    if ($SasUri.Contains('?')) { $separator = '&' }
    $listUri = '{0}{1}comp=blocklist' -f $SasUri, $separator
    & $Invoker @{
        Method      = 'PUT'
        Uri         = $listUri
        Body        = $xml.ToString()
        ContentType = 'application/xml'
    } | Out-Null
}

function Send-IntunePackage {
    <#
    .SYNOPSIS
        Publishes a Win32 app to Intune when -Upload is set and secrets are present.

    .DESCRIPTION
        The default result is a preview. No Graph call is made unless -Upload is set.
        Required environment variables, or matching parameters: SAF_INTUNE_TENANT_ID, SAF_INTUNE_CLIENT_ID, SAF_INTUNE_CLIENT_SECRET.
        The app registration needs the application permission DeviceManagementApps.ReadWrite.All with admin consent.
        v0.1 does not create an assignment. Client-secret values are not written to the returned object.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        $Manifest,
        [string]$IntuneWinPath,
        [switch]$Upload,
        [string]$TenantId = $env:SAF_INTUNE_TENANT_ID,
        [string]$ClientId = $env:SAF_INTUNE_CLIENT_ID,
        [string]$ClientSecret = $env:SAF_INTUNE_CLIENT_SECRET,
        [string]$GraphBaseUri = 'https://graph.microsoft.com/beta',
        [scriptblock]$HttpInvoker,
        [int]$MaxAttempts = 30,
        [int]$PollDelaySeconds = 5
    )

    $plan = Get-IntuneUploadPlan -Manifest $Manifest -IntuneWinPath $IntuneWinPath
    $secretsReady = -not [string]::IsNullOrWhiteSpace($TenantId) -and -not [string]::IsNullOrWhiteSpace($ClientId) -and -not [string]::IsNullOrWhiteSpace($ClientSecret)
    if (-not $Upload) {
        return [pscustomobject]@{
            Status            = 'Disabled'
            Reason            = 'Upload is off. Pass -Upload to publish. No Graph call was made.'
            Plan              = $plan
            SecretsConfigured = $secretsReady
            Steps             = @()
            AppId             = ''
            ContentVersionId  = ''
        }
    }
    if (-not $secretsReady) {
        return [pscustomobject]@{
            Status            = 'Skipped'
            Reason            = 'SAF_INTUNE_TENANT_ID, SAF_INTUNE_CLIENT_ID, and SAF_INTUNE_CLIENT_SECRET must all be set. No Graph call was made.'
            Plan              = $plan
            SecretsConfigured = $false
            Steps             = @()
            AppId             = ''
            ContentVersionId  = ''
        }
    }
    if (-not $PSCmdlet.ShouldProcess([string]$Manifest.name, 'Upload Win32 app to Intune')) {
        return [pscustomobject]@{
            Status            = 'Preview'
            Reason            = 'WhatIf is set. No Graph call was made.'
            Plan              = $plan
            SecretsConfigured = $true
            Steps             = @()
            AppId             = ''
            ContentVersionId  = ''
        }
    }
    if (-not $plan.IntuneWinPresent) {
        throw 'Pass an existing .intunewin path with -Upload.'
    }

    if (-not $HttpInvoker) {
        $HttpInvoker = { param($Request) Invoke-SafDefaultHttp -Request $Request }
    }

    $steps = New-Object System.Collections.Generic.List[string]
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $tokenBody = 'client_id={0}&client_secret={1}&scope={2}&grant_type=client_credentials' -f @(
        [uri]::EscapeDataString($ClientId),
        [uri]::EscapeDataString($ClientSecret),
        [uri]::EscapeDataString('https://graph.microsoft.com/.default')
    )
    $tokenResponse = & $HttpInvoker @{
        Method      = 'POST'
        Uri         = $tokenUri
        Body        = $tokenBody
        ContentType = 'application/x-www-form-urlencoded'
    }
    $steps.Add('token')
    $token = [string](Get-SafProp -Object $tokenResponse -Name @('access_token'))
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'The token endpoint did not return an access token.'
    }

    $base = $GraphBaseUri.TrimEnd('/')
    $auth = @{ Authorization = "Bearer $token" }
    $appJson = ConvertTo-SafJson -Value $plan.AppBody
    $app = & $HttpInvoker @{
        Method      = 'POST'
        Uri         = "$base/deviceAppManagement/mobileApps"
        Headers     = $auth
        Body        = $appJson
        ContentType = 'application/json'
    }
    $steps.Add('create-app')
    $appId = [string](Get-SafProp -Object $app -Name @('id'))
    if ([string]::IsNullOrWhiteSpace($appId)) {
        throw 'Graph did not return an app id.'
    }

    $version = & $HttpInvoker @{
        Method      = 'POST'
        Uri         = "$base/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions"
        Headers     = $auth
        Body        = '{}'
        ContentType = 'application/json'
    }
    $steps.Add('content-version')
    $versionId = [string](Get-SafProp -Object $version -Name @('id'))

    $metadata = Get-SafIntuneWinMetadata -Path $IntuneWinPath
    $fileBody = ConvertTo-SafJson -Value ([ordered]@{
        '@odata.type' = '#microsoft.graph.mobileAppContentFile'
        name          = [string]$metadata.FileName
        size          = [int64]$metadata.UnencryptedSize
        sizeEncrypted = [int64]$metadata.EncryptedBytes.Length
        isDependency  = $false
        manifest      = $null
    })
    $file = & $HttpInvoker @{
        Method      = 'POST'
        Uri         = "$base/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$versionId/files"
        Headers     = $auth
        Body        = $fileBody
        ContentType = 'application/json'
    }
    $steps.Add('create-file')
    $fileId = [string](Get-SafProp -Object $file -Name @('id'))
    $fileUri = "$base/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$versionId/files/$fileId"

    $ready = Wait-SafFileState -Uri $fileUri -Token $token -Desired 'azureStorageUriRequestSuccess' -FailStates @('azureStorageUriRequestFailed') -Invoker $HttpInvoker -MaxAttempts $MaxAttempts -DelaySeconds $PollDelaySeconds
    $steps.Add('wait-sas')
    $sas = [string](Get-SafProp -Object $ready -Name @('azureStorageUri'))
    if ([string]::IsNullOrWhiteSpace($sas)) {
        throw 'Graph did not return an Azure Storage URI.'
    }

    Send-SafBlobBlocks -SasUri $sas -Bytes $metadata.EncryptedBytes -Invoker $HttpInvoker
    $steps.Add('upload-blocks')

    $commitBody = ConvertTo-SafJson -Value ([ordered]@{ fileEncryptionInfo = $metadata.Encryption })
    & $HttpInvoker @{
        Method      = 'POST'
        Uri         = "$fileUri/commit"
        Headers     = $auth
        Body        = $commitBody
        ContentType = 'application/json'
    } | Out-Null
    $steps.Add('commit')
    Wait-SafFileState -Uri $fileUri -Token $token -Desired 'commitFileSuccess' -FailStates @('commitFileFailed') -Invoker $HttpInvoker -MaxAttempts $MaxAttempts -DelaySeconds $PollDelaySeconds | Out-Null
    $steps.Add('wait-commit')

    $patchBody = ConvertTo-SafJson -Value ([ordered]@{
        '@odata.type'           = '#microsoft.graph.win32LobApp'
        committedContentVersion = $versionId
    })
    & $HttpInvoker @{
        Method      = 'PATCH'
        Uri         = "$base/deviceAppManagement/mobileApps/$appId"
        Headers     = $auth
        Body        = $patchBody
        ContentType = 'application/json'
    } | Out-Null
    $steps.Add('patch-app')

    return [pscustomobject]@{
        Status            = 'Uploaded'
        Reason            = 'Win32 app content was committed. No assignment was created.'
        Plan              = $plan
        SecretsConfigured = $true
        Steps             = $steps.ToArray()
        AppId             = $appId
        ContentVersionId  = $versionId
    }
}
