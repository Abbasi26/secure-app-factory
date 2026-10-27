# Authenticode is a Windows check. Other platforms report Unavailable and the caller fails closed when a signature is required.

function Get-SafAuthenticode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Get-SafIsWindows)) {
        return [pscustomobject]@{
            Status     = 'Unavailable'
            Subject    = ''
            Thumbprint = ''
            Platform   = 'NonWindows'
        }
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $subject = ''
    $thumbprint = ''
    if ($signature.SignerCertificate) {
        $subject = [string]$signature.SignerCertificate.Subject
        $thumbprint = [string]$signature.SignerCertificate.Thumbprint
    }
    return [pscustomobject]@{
        Status     = [string]$signature.Status
        Subject    = $subject
        Thumbprint = $thumbprint
        Platform   = 'Windows'
    }
}
