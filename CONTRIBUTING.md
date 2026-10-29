# Contributing

Secure App Factory is a small packaging pipeline. Changes should stay auditable: a reader should be able to see what was downloaded, what was checked, and what was written.

## Setup

- PowerShell 7 (`pwsh`). CI runs PowerShell 7.6 LTS. Windows PowerShell 5.1 is not a target.
- Pester 5 for tests: `Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser`
- No Azure tenant, no Intune app registration, and no network access are required to run the tests or the demo.

```powershell
pwsh -NoLogo -File ./scripts/Invoke-Tests.ps1
pwsh -NoLogo -File ./demo/Invoke-Demo.ps1
```

## What a change should include

- Keep comments, messages, and documentation in English.
- Keep `.ps1`, `.psm1`, and `.psd1` files ASCII-only. If a PowerShell file must contain non-ASCII text, save it as UTF-8 with a BOM.
- Do not add secrets, tenant ids, host names from a real environment, or telemetry.
- Network access, file replacement, installers, tool downloads, lock-file writes, and Intune uploads stay behind an explicit switch. The default path previews or reads.
- Do not vendor PSAppDeployToolkit or `IntuneWinAppUtil.exe`. Both are downloaded at build time from the pinned URLs in `src/SecureAppFactory/data/external-tools.json`, and only when the caller passes the matching switch.
- Add or update a Pester test when you change schema, trust, or a write switch. Tests must pass offline.
- Update `CHANGELOG.md` under `0.1.x` or the next version you are actually shipping. Do not document a command that the module does not export.

## Adding an application

The short path, after you downloaded and reviewed the installer yourself:

```powershell
Import-Module ./src/SecureAppFactory/SecureAppFactory.psd1 -Force
New-SafAppManifest -Id example -Name "Example" -Version 1.2.3 -Publisher "Example Ltd" `
  -Url https://downloads.example.org/example-1.2.3-x64.exe -InstallerPath ./example-1.2.3-x64.exe `
  -InstallArguments "/S" -UninstallPath "{ProgramFiles}\Example\uninstall.exe" -UninstallArguments "/S" `
  -DetectionPath "{ProgramFiles}\Example\example.exe" -SignatureSubject "Example Ltd" -SignatureThumbprint <40 hex>
pwsh -NoLogo -File ./scripts/Test-Apps.ps1
```

Then check each point below by hand.

1. Create `apps/<id>/app.yaml`. `<id>` is the directory name and must match `[a-z0-9-]+`.
2. Pin `source.url` to an https URL with no embedded credentials, or set `source.type` to `evergreen` and pin `version` to the exact Evergreen result you intend to package. A newer vendor release does not replace the pin.
3. Set `trust.value` to the SHA-256 of that exact file. Commit a matching `apps/<id>/lock.json`, or leave the hash empty and record it locally with `-TrustOnFirstUse` on a file you have reviewed. `-TrustOnFirstUse` never overwrites an existing lock.
4. If the installer is Authenticode-signed, set `trust.signature.required` to `true`, set `subjectContains`, and pin the leaf certificate SHA-1 thumbprint. If it is not signed, set `required` to `false` and say so in a comment. Do not pretend an unsigned file is signed.
5. The examples are 7-Zip and Notepad++ because their installers are published for redistribution. Do not add an application whose vendor forbids redistributing the installer.

## Pull requests

Open a pull request against `main`. The Package workflow runs the offline tests, the catalog check, the Linux demo, and the Windows build. It does not upload to Intune unless someone runs the workflow manually and sets `upload` to true. Do not put secret values in the pull request, the workflow file, or a fixture.
