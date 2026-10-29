# Changelog

## Unreleased

- CI: every `pwsh` job runs PowerShell 7.6 LTS (7.6.9, SHA-256 pinned, version asserted) through `.github/actions/install-pwsh-7-6` instead of the runner's preinstalled pwsh. PowerShell 7.4 and 7.5 reach end of support on 10 Nov 2026 ([support lifecycle](https://learn.microsoft.com/en-us/powershell/scripting/install/powershell-support-lifecycle)). The module still requires PowerShell 7.0 or later; Windows PowerShell 5.1 is not a target, so there is no 5.1 job.

## 0.2.0 - 2026-10-28

- `Test-SafAppCatalog` reviews every `apps/<id>` folder offline: schema and YAML errors, a missing SHA-256 pin, a manifest and lock that disagree, a lock recorded for a different URL, a URL and file name that do not contain the version, a signature rule without a leaf thumbprint, uninstall or detection paths with a fixed drive letter, duplicate URLs, and folder names `-App` cannot select. Severity is Error, Warning, or Info. `ConvertTo-SafCatalogMarkdown` renders the findings.
- `scripts/Test-Apps.ps1` prints the findings, appends Markdown to `-SummaryPath`, and exits 1 on an error (or on a warning with `-FailOnWarning`). The Package workflow has a new Catalog check job that runs it.
- `New-SafAppManifest` writes `apps/<id>/app.yaml` and `lock.json` from parameters. The hash comes from `-Sha256` or from a local file passed as `-InstallerPath`. The generated manifest is validated against the schema before anything is written. Refuses to overwrite without `-Force`; supports `-WhatIf`. Ids are checked case-sensitively.
- `actions/checkout` and `actions/upload-artifact` are pinned to commit SHAs.
- ROADMAP.md with good first issues, issue forms (bug, feature, new example app), and a pull request template.

## 0.1.0 - 2026-10-21

First release of the packaging template.

- Package manifests in `apps/<name>/app.yaml` with an https URL or an Evergreen application name, a SHA-256 pin, an optional lock file, install and uninstall commands, and a file or registry detection rule.
- PowerShell 7 module `SecureAppFactory` with `Get-SourceInstaller`, `Test-InstallerTrust`, `New-PsadtPackage`, `New-IntuneWinPackage`, `New-PackageSbom`, `New-PackageProvenance`, `Test-PackageInstall`, `Get-IntuneUploadPlan`, `Send-IntunePackage`, `New-PackageReport`, and `Invoke-SafPipeline`.
- Example apps: 7-Zip 26.04 x64 (hash pin, signature not required) and Notepad++ 8.9.8.1 x64 (hash pin plus leaf certificate subject and thumbprint).
- GitHub Actions workflow that runs Pester, the offline demo, and a `windows-latest` build with a silent install/uninstall smoke test, a PSAppDeployToolkit 4.1.8 folder, an `.intunewin`, a CycloneDX 1.6 SBOM, provenance, and `REPORT.md`.
- Intune upload through Microsoft Graph, off unless `-Upload` is passed and `SAF_INTUNE_TENANT_ID`, `SAF_INTUNE_CLIENT_ID`, and `SAF_INTUNE_CLIENT_SECRET` are all set. v0.1 does not create an assignment.
- Offline demo that copies local fixtures and writes the same report shape without downloads, installs, or Graph calls.
