# ScanProof end-to-end tests

Live tests for [ScanProof](https://github.com/abdelrahman-eladwy/scanproof). Unit tests live with
the code and run offline against recorded fixtures; this repository runs ScanProof against
**real** CI platforms and scanners, to prove those fixtures still match reality and that release
gates really block.

Every workflow installs ScanProof from the code repository's `main` branch by default. Run one
manually to test any branch, tag or commit: **Actions > workflow > Run workflow**, set
`scanproof_ref`. The job summary records the exact ScanProof commit tested.

## Workflows

| Workflow | Runs | What it proves |
|---|---|---|
| [`demo`](.github/workflows/demo.yml) | daily, push to `main`, manual | Two green-looking release pipelines: one VERIFIED, one BLOCKED |
| [`github-contract`](.github/workflows/github-contract.yml) | daily, manual | ScanProof verifies its own run: masked steps and jobs, skipped jobs, matrices, reusable workflows, scope-free reports |
| [`attestation-contract`](.github/workflows/attestation-contract.yml) | weekly, manual | Sigstore attestations from this run: correct signer, wrong signer, reusable-workflow pinning |
| [`release-gate-contract`](.github/workflows/release-gate-contract.yml) | manual | A failed gate stops the downstream deploy job. **Expected red overall**; `assert-contract` must be green |
| [`platforms-contract`](.github/workflows/platforms-contract.yml) | weekly, manual | Real Azure DevOps and Bitbucket APIs, and a throwaway Jenkins running one pipeline per masking pattern |
| [`gitlab-contract`](.github/workflows/gitlab-contract.yml) | weekly, manual | `scanproof inspect` still reads real public gitlab.com pipelines (API drift) |
| [`fixtures`](.github/workflows/fixtures.yml) | manual | Generates real reports from every supported scanner (no ScanProof involved) |

`reusable-attest.yml` and `reusable-scan.yml` are called by the contract workflows; they are part
of what is being tested, not standalone jobs.

## Layout

| Path | Contents |
|---|---|
| `policies/` | ScanProof policies each workflow verifies against, one folder per workflow. Each file states the expected exit code. |
| `jenkins/` | Configuration-as-code Jenkins image and one pipeline per masking pattern |
| `scripts/` | Collectors that save sanitized API responses (allow-listed fields only) |
| `targets/` | Deliberately vulnerable scan inputs ([never deploy](targets/README.md)) |
| `.github/actions/install-scanproof/` | Installs ScanProof at a given ref and records the commit |

## Refreshing ScanProof's test fixtures

1. Push to a disposable branch matching the workflow's trigger: `fixtures/scanners/<name>`,
   `fixtures/github/<name>`, `fixtures/attest/<name>`, `fixtures/gate/<name>`,
   `fixtures/platforms/<name>` or `fixtures/gitlab/<name>`.
2. The workflow commits its raw output to that branch under `generated-fixtures/`.
3. Review it, copy what you need into `tests/fixtures/` in the code repository (see its
   [fixtures README](https://github.com/abdelrahman-eladwy/scanproof/blob/main/tests/fixtures/README.md)),
   and update the affected unit tests.
4. Delete the branch.

Reports regenerated here carry this repository's identity (`abdelrahman-eladwy/scanproof-e2e`)
in run URLs, artifact paths (`targets/...`) and Sigstore signer URIs. Update the expected values
in the code repository's unit tests when you replace older fixtures.

## Permissions

Workflows use the run's own `GITHUB_TOKEN` with read-only scopes, except the jobs that sign
attestations (`id-token: write`, `attestations: write`) and the `publish` jobs that commit to
`fixtures/**` branches (`contents: write`). No other secrets are needed. Third-party actions are
pinned to commit SHAs; Dependabot keeps them current.

## License

Apache 2.0, same as ScanProof.
