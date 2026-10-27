# Restore report: secure-app-factory

- Source transcript: `bc-516efa25-3ab6-5f74-8a7e-3571410fcdea.jsonl`
- Method: replay of `search_replace` editFileResult unified diffs in order; binary demo fixtures recreated from transcript Python one-liner
- NVIDIA / OpenRouter generation: **not needed** (full tree reconstructable; all tests green)
- Restored from transcript diffs: 36 paths via search_replace
- Filled from transcript shell:
  - `demo/fixtures/7zip/installer.bin`
  - `demo/fixtures/notepadpp/installer.bin`
  (sha256 matches existing `installer.sha256` lock files)
- Tests: Pester 5+/6 → **22 passed, 0 failed** (matches transcript)
- Demo fixtures are mock binaries, not real installers
- Ready to push: **yes**
- Gaps: none functional. Docs/workflows (LICENSE, README, .github, …) restored; an intermediate `find` in the transcript omitted some of them but they exist in the final commit set.
