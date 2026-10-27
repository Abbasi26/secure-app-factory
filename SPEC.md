# SPEC: Secure App Factory

## Original task

Build v0.1 of **Secure App Factory**, an open-source GitHub Actions based template and PowerShell toolkit for building Windows software packages for Intune/MECM with supply-chain hygiene. It covers fetching the vendor installer, verifying hash and Authenticode signature, wrapping it with PSAppDeployToolkit (PSADT v4), creating the .intunewin, generating an SBOM (CycloneDX) and provenance metadata, running a silent install/uninstall smoke test on a windows-latest runner, and publishing artifacts. Follow ALL rules in uploads/gemeinsame_regeln.md. Before writing the README comparison, briefly research existing tools (e.g. Winget-AutoUpdate, Evergreen, IntuneWin32App, PSADT, Chocolatey, Patch My PC) and position this honestly, as a transparent, auditable pipeline template.

v0.1 scope:
- `apps/<name>/app.yaml` package definition:
  - source (URL or Evergreen query), expected publisher / signature subject, hash pinning or a trust-on-first-use lock file
  - install/uninstall commands and detection rule
- PowerShell module with:
  - Get-SourceInstaller
  - Test-InstallerTrust (Authenticode + hash)
  - New-PsadtPackage
  - New-IntuneWinPackage (use Microsoft's IntuneWinAppUtil if license allows downloading at build time, otherwise document it)
  - New-PackageSbom
  - Test-PackageInstall (smoke test)
- A GitHub Actions workflow running the whole pipeline on windows-latest for 2 example apps with freely redistributable installers (e.g. 7-Zip, Notepad++). It produces artifacts plus a Markdown package report.
- Optional Intune upload step via Graph, disabled by default; it only runs with explicit secrets configured, which are documented, never included.
- Demo/dry-run mode that runs on Linux using mocked downloads to show the report.
- Pester tests with mocks for the trust checks and the YAML schema.

## Shared rules

See GEMEINSAME_REGELN.md (extracted from transcript).
