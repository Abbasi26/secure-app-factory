# Updating an app version and hash pins

This walkthrough updates a reviewed `apps/<id>` entry when the vendor publishes a new installer release (for example 1.2.3 to 1.2.4). The goal is a small, auditable pull request that changes only the pinned version, source, trust data, and related documentation for that app.

The catalog check is offline. It verifies that the manifest and `lock.json` are consistent and schema-valid; it does not prove that a new download is authentic. Review the vendor source and the installer before you change the pins.

## 1. Review the vendor release

1. Confirm the exact version, architecture, and file name from the vendor's release page or release notes.
2. Record the source you trust for this review (release page, published checksums, and signature details if available).
3. Download the new installer to a local, temporary location you control. Do not add the installer binary to the repository.
4. Do not run the installer outside an isolated test environment. Before the first upload or deployment, verify install, uninstall, and detection on a test machine.

## 2. Verify the installer locally

Compute the SHA-256 of the local file:

```powershell
Get-FileHash -Algorithm SHA256 -Path .\example-1.2.4-x64.exe
```

Compare the digest with the value the vendor publishes for that exact file and architecture. The SHA-256 in `app.yaml` (`trust.value`) and `lock.json` (`value`) is the hash of the installer bytes. It is not the same as the SHA-1 thumbprint of an Authenticode signing certificate.

For a signed installer on Windows, inspect Authenticode before updating the pin:

```powershell
$signature = Get-AuthenticodeSignature -FilePath .\example-1.2.4-x64.exe
$signature.Status
$signature.SignerCertificate.Subject
$signature.SignerCertificate.Thumbprint
```

`Status` should be `Valid` for the reviewed file. Record the signer subject and the leaf certificate thumbprint. Do not weaken or remove a required signature rule because a certificate changed; a renewed certificate must be reviewed and explained in the pull request.

For an unsigned installer, keep `trust.signature.required` set to `false` and do not pretend the file is signed. In that case the SHA-256 pin is the trust control.

## 3. Update `app.yaml`

Edit `apps/<id>/app.yaml` for the same app id. In a typical version update, change at least:

- `version` to the new release (for example `"1.2.4"`).
- `source.url` to the exact https URL for that release.
- `source.fileName` to the exact installer file name.
- `trust.value` to the verified SHA-256.
- comments or descriptions that mention the old version, if they would become misleading.

If the installer is signed and the signature policy changes, review and update:

- `trust.signature.required` (keep `true` for signed installers).
- `trust.signature.subjectContains` when the expected publisher name in the certificate subject changes.
- `trust.signature.thumbprint` when the leaf certificate changes. This is the certificate SHA-1 thumbprint shown by Authenticode, not the installer SHA-256.

Keep install, uninstall, detection, and `psadt` settings accurate for the new version. If the vendor changed paths, arguments, product behavior, or packaging, update those fields only after testing; do not guess.

## 4. Update `lock.json`

Edit `apps/<id>/lock.json` so it matches the same reviewed installer:

```json
{
  "algorithm": "SHA256",
  "value": "<verified installer sha256>",
  "source": "https://downloads.example.org/example-1.2.4-x64.exe",
  "recordedAt": "2026-11-16T00:00:00Z",
  "recordedBy": "pinned"
}
```

Keep `algorithm` as `SHA256`, set `value` to the same hash as `trust.value`, and set `source` to the same URL as `source.url`. Use a current UTC timestamp for `recordedAt`. Do not add invented version or signature fields to `lock.json`; the schema and catalog checks expect the existing lock format.

## 5. Manual edit or `New-SafAppManifest`

A careful manual edit is usually the safest way to update an existing app because it preserves reviewed comments and fields that are not part of the `New-SafAppManifest` parameters (for example custom `psadt` settings, descriptions, or other existing manifest content).

`New-SafAppManifest` can help create a fresh, schema-validated manifest and lock file, but be aware of its behavior:

- It does not download anything. Pass `-Sha256` for a vendor-published digest or `-InstallerPath` for a local file you already reviewed.
- It refuses to overwrite an existing app unless `-Force` is set.
- With `-Force`, it replaces both `app.yaml` and `lock.json` completely. Review the generated files before committing so you do not lose existing reviewed fields or comments.
- It writes `lock.json` with `recordedBy` set to `new-safappmanifest`.
- `-TrustOnFirstUse` in the packaging pipeline records a lock only when no hash pin exists yet and the signature policy passed; it never overwrites an existing lock.

If you use `New-SafAppManifest` as a starting point, compare the result with the previous manifest and keep any app-specific settings that still apply.

## 6. Run checks

Run the offline catalog check for the app manifests:

```powershell
pwsh -NoLogo -File ./scripts/Test-Apps.ps1
```

Before opening a pull request, also run the checks required by this repository:

```powershell
pwsh -NoLogo -File ./scripts/Invoke-Tests.ps1
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error"
pre-commit run --all-files
```

These checks should still pass for a documentation-only change. For an app update, also perform the relevant Windows validation for the changed installer (including a smoke test on a test machine when appropriate) and report what you actually ran.

## 7. Prepare the pull request

Keep the diff small and limited to the app update. In the pull request, include:

- the old and new version;
- the vendor source/release page used for the review;
- the verified installer SHA-256 and, for signed installers, the reviewed signer subject and leaf thumbprint;
- the reason for any certificate or signature-policy change;
- the commands and tests you actually ran.

Do not commit installer binaries, secrets, tokens, real host names, or personal data. If you change a pin, keep `app.yaml` and `lock.json` consistent in the same pull request.
