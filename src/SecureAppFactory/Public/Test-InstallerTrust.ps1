function Test-SafSignaturePolicy {
    param($Manifest, $Observed)

    $requiredValue = Get-SafProp -Object $Manifest -Name @('trust', 'signature', 'required')
    $required = $false
    if ($requiredValue -eq $true) { $required = $true }
    $subjectNeedle = [string](Get-SafProp -Object $Manifest -Name @('trust', 'signature', 'subjectContains'))
    $thumbprint = ([string](Get-SafProp -Object $Manifest -Name @('trust', 'signature', 'thumbprint'))).Trim()
    $status = [string]$Observed.Status
    $subject = [string]$Observed.Subject
    $observedThumb = ([string]$Observed.Thumbprint).Trim()
    $reasons = New-Object System.Collections.Generic.List[string]
    $match = $true

    $broken = @('HashMismatch', 'NotTrusted', 'UnknownError', 'Incompatible')
    if ($broken -contains $status) {
        $match = $false
        $reasons.Add("Authenticode status is $status.")
    }
    elseif ($required) {
        if ($status -eq 'Unavailable') {
            $match = $false
            $reasons.Add('Authenticode cannot be checked on this platform, and the manifest requires a signature.')
        }
        elseif ($status -ne 'Valid') {
            $match = $false
            $reasons.Add("Authenticode status is $status. The manifest requires a valid signature.")
        }
        elseif (-not [string]::IsNullOrWhiteSpace($subjectNeedle) -and ($subject.IndexOf($subjectNeedle, [StringComparison]::OrdinalIgnoreCase) -lt 0)) {
            $match = $false
            $reasons.Add("Signer subject does not contain '$subjectNeedle'. Subject: $subject")
        }
    }
    else {
        if ($status -eq 'Valid' -and -not [string]::IsNullOrWhiteSpace($subjectNeedle) -and ($subject.IndexOf($subjectNeedle, [StringComparison]::OrdinalIgnoreCase) -lt 0)) {
            $match = $false
            $reasons.Add("The file is signed, but the subject does not contain '$subjectNeedle'. Subject: $subject")
        }
        if ($status -eq 'Unavailable') {
            $reasons.Add('Authenticode was not checked on this platform. The manifest does not require a signature.')
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($thumbprint)) {
        $normalizedObserved = ($observedThumb -replace '\s', '').ToUpperInvariant()
        $normalizedPin = ($thumbprint -replace '\s', '').ToUpperInvariant()
        if ($status -ne 'Valid' -or $normalizedObserved -ne $normalizedPin) {
            $match = $false
            $reasons.Add("Certificate thumbprint does not match the pin. Observed: $observedThumb")
        }
    }

    return [pscustomobject]@{
        Match   = $match
        Reasons = $reasons.ToArray()
    }
}

function Test-InstallerTrust {
    <#
    .SYNOPSIS
        Checks a downloaded installer against the hash pin and the Authenticode policy.

    .DESCRIPTION
        Returns an object. Passed is false when the hash or the signature policy fails.
        Invoke-SafPipeline stops the build in that case. -TrustOnFirstUse writes a lock file
        only when no pin exists yet and the signature policy passes. It never overwrites a pin.

    .PARAMETER ExpectedHash
        Hash to compare when the production pin should not be used, such as a demo fixture pin.

    .PARAMETER Demo
        Marks the result as a demo. The production manifest hash is still checked against the lock file
        when both exist, and it is not compared to the fixture bytes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        $Manifest,
        [string]$LockPath,
        [switch]$TrustOnFirstUse,
        [string]$ExpectedHash,
        [switch]$Demo,
        [scriptblock]$SignatureInspector
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Installer not found: $Path"
    }

    $reasons = New-Object System.Collections.Generic.List[string]
    $actual = Get-SafSha256 -Path $Path
    $manifestHash = ''
    if (Test-SafHasProp -Object (Get-SafProp -Object $Manifest -Name @('trust')) -Name 'value') {
        $manifestHash = ConvertTo-SafHex ([string](Get-SafProp -Object $Manifest -Name @('trust', 'value')))
    }
    $lock = $null
    if (-not [string]::IsNullOrWhiteSpace($LockPath)) {
        $lock = Read-SafLock -Path $LockPath
    }
    $lockHash = ''
    if ($lock) {
        $lockHash = ConvertTo-SafHex ([string]$lock.value)
    }
    if ($manifestHash -and $lockHash -and $manifestHash -ne $lockHash) {
        $reasons.Add('Manifest trust.value and the lock file do not agree. Update them together in a reviewed change.')
    }

    $expected = ''
    $expectedSource = 'none'
    if ($Demo) {
        if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {
            throw 'Demo trust check requires -ExpectedHash from the fixture pin.'
        }
        $expected = ConvertTo-SafHex $ExpectedHash
        $expectedSource = 'demo-fixture'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($ExpectedHash)) {
        $expected = ConvertTo-SafHex $ExpectedHash
        $expectedSource = 'parameter'
    }
    elseif ($manifestHash) {
        $expected = $manifestHash
        $expectedSource = 'manifest'
    }
    elseif ($lockHash) {
        $expected = $lockHash
        $expectedSource = 'lock'
    }

    if ($SignatureInspector) {
        $observed = & $SignatureInspector $Path
    }
    else {
        $observed = Get-SafAuthenticode -Path $Path
    }
    $signature = Test-SafSignaturePolicy -Manifest $Manifest -Observed $observed

    $lockAction = 'none'
    $hashMatch = $false
    if ([string]::IsNullOrWhiteSpace($expected)) {
        $lockAction = 'preview'
        $reasons.Add("No hash pin. Observed SHA-256 is $actual. Re-run with -TrustOnFirstUse to record a lock file. Nothing was written.")
        if ($TrustOnFirstUse) {
            if ([string]::IsNullOrWhiteSpace($LockPath)) {
                throw 'Pass -LockPath with -TrustOnFirstUse so the pin has a file to write.'
            }
            if (-not $signature.Match) {
                $reasons.Add('The lock file was not written because the signature policy failed.')
            }
            else {
                $sourceUri = [string](Get-SafProp -Object $Manifest -Name @('source', 'url'))
                Write-SafLock -Path $LockPath -Hash $actual -Source $sourceUri
                $lockAction = 'written'
                $expected = $actual
                $expectedSource = 'trust-on-first-use'
                $hashMatch = $true
                $reasons.Add("Recorded SHA-256 $actual in $LockPath.")
            }
        }
    }
    else {
        $hashMatch = ($actual -eq $expected)
        if (-not $hashMatch) {
            $reasons.Add("SHA-256 does not match the $expectedSource pin. Expected $expected. Observed $actual.")
            if ($TrustOnFirstUse) {
                $reasons.Add('-TrustOnFirstUse does not overwrite an existing pin.')
            }
        }
    }

    foreach ($reason in @($signature.Reasons)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$reason)) {
            $reasons.Add([string]$reason)
        }
    }

    $pinsAgree = $true
    if ($manifestHash -and $lockHash -and $manifestHash -ne $lockHash) {
        $pinsAgree = $false
    }

    $passed = $hashMatch -and $signature.Match -and $pinsAgree
    return [pscustomobject]@{
        Passed         = $passed
        Demo           = [bool]$Demo
        Hash           = [pscustomobject]@{
            Actual   = $actual
            Expected = $expected
            Match    = $hashMatch
            Source   = $expectedSource
        }
        ProductionPin  = [pscustomobject]@{
            Value          = $manifestHash
            LockValue      = $lockHash
            AgreesWithLock = $pinsAgree
            ComparedToFile = -not [bool]$Demo
        }
        Signature      = [pscustomobject]@{
            Status     = [string]$observed.Status
            Subject    = [string]$observed.Subject
            Thumbprint = [string]$observed.Thumbprint
            Required   = [bool](Get-SafProp -Object $Manifest -Name @('trust', 'signature', 'required'))
            Match      = [bool]$signature.Match
            Platform   = [string]$observed.Platform
            Mock       = [bool]($Demo -or ($null -ne $SignatureInspector))
        }
        LockAction     = $lockAction
        Reasons        = $reasons.ToArray()
    }
}
