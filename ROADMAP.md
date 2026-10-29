# Roadmap

Secure App Factory builds one reviewed installer at a time. It stays a template, not a catalog service and not an endpoint agent.

## 0.2 (this branch)

- `Test-SafAppCatalog` and `scripts/Test-Apps.ps1`: an offline review of every `apps/<id>` folder. Schema errors, a missing or disagreeing pin, a lock recorded for another URL, a URL that does not name the version, a signature rule without a thumbprint, fixed drive letters, and duplicate URLs. Markdown output for the job summary. A new CI job runs it.
- `New-SafAppManifest`: writes `app.yaml` and `lock.json` from parameters, hashes a local installer you already reviewed, validates the result against the schema, and supports `-WhatIf` and `-Force`. No download.
- GitHub Actions in the workflow are pinned to commit SHAs.
- An issue form for proposing a new example app.

## Next

- Run `-SmokeTest -SmokeTestMode Toolkit` in CI so the generated PSADT script is installed once per app, not only the vendor command.
- MSI support: read the ProductCode from the MSI and offer an MSI product-code detection rule.
- `Find-SafUpdate`: compare a pinned version with Evergreen or the vendor's release feed and open nothing, only report. The pin is still changed by a human.
- Certificate authentication for Graph and updating an existing Win32 app instead of creating a new one.
- Timestamp counter-signature checks.
- Dependabot for the pinned action SHAs.

## Good first issues

1. **A third example app** with a vendor-published SHA-256 and a redistributable installer. Use `New-SafAppManifest`, then `scripts/Test-Apps.ps1`. Use the "New example app" issue form first.
2. **`-FailOnWarning` in CI** once the warnings are understood: add a workflow input or a repository variable.
3. **JSON output** for `scripts/Test-Apps.ps1` (`-JsonPath`) so other tools can read the findings.
4. ~~**Catalog check: architecture hint**. Warn when `architecture: x64` but the file name contains `x86`, `win32`, or `arm64`.~~ Done in 0.2.1.
5. **Docs**: a short walkthrough from "vendor publishes 1.2.4" to a reviewed pull request that updates both the manifest and `lock.json`.
6. **Report**: list the catalog findings for the built app at the top of `REPORT.md`.

Out of scope: an app catalog with automatic upgrades, assignment to groups, and running anything on endpoints.
