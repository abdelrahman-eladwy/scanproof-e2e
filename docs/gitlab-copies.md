# GitLab copies contract: setup

The GitLab half of [`copies-contract`](../.github/workflows/copies-contract.yml) checks ScanProof's
copy completeness ([scanproof#65](https://github.com/abdelrahman-eladwy/scanproof/issues/65)) on
**real** gitlab.com child pipelines. It needs two GitLab projects that only the maintainer can
create. Both are read **anonymously**: no GitLab token is stored in this repository.

| Project | Visibility | Contents |
|---|---|---|
| `scanproof-copies` | **Public** | [`gitlab/copies/parent/`](../gitlab/copies/parent/) |
| `scanproof-copies-private` | **Private** | [`gitlab/copies/private/`](../gitlab/copies/private/) |

## What it proves

| Branch of `scanproof-copies` | Pipeline | Scenarios ([main](../policies/copies/gitlab-main-scenarios.json), [inaccessible](../policies/copies/gitlab-inaccessible-scenarios.json)) |
|---|---|---|
| `main` | `svc-a > copy-sast`, `svc-b > copy-sast` | both declared: exit 0 · `svc-c` declared (no such trigger, i.e. removed): exit 1 `REQUIRED_COPY_ABSENT` · production without `copies`: exit 2 `COPIES_UNDECLARED` · production with `copies`: exit 0 · compatible without `copies`: exit 0 + warning |
| `inaccessible` | the same, plus `svc-private`, a child in the private project (403 anonymously) | `svc-private` declared: exit 2 `JOB_MAYBE_IN_UNREADABLE_PIPELINE` (unknown, **not** absent) · only `svc-a`, `svc-b` declared: exit 0 + "could not be read" warning · production without `copies`: exit 2 |

How ScanProof tells a missing copy from an unreadable pipeline:
[Missing or unreadable](https://github.com/abdelrahman-eladwy/scanproof/blob/main/docs/advanced-policy.md#missing-or-unreadable-when-absence-is-proven).

Each run uses the latest **successful** pipeline of each branch and fails if it is older than 8
days, so a broken schedule shows up as a red contract, not a silent pass.

## Setup (one time, about 15 minutes)

gitlab.com requires a verified account to use its shared runners.
Usage is small: 4 short Semgrep jobs per week. Put nothing secret in either project.

1. **Private project.** Create `scanproof-copies-private`, visibility **Private**, empty. Push the
   private config to `main`:

   ```bash
   git clone https://github.com/abdelrahman-eladwy/scanproof-e2e && cd scanproof-e2e/gitlab/copies/private
   git init -b main && git add . && git commit -m "scanproof copies contract (private child)"
   git push https://gitlab.com/<you>/scanproof-copies-private.git main
   ```

2. **Public project.** Create `scanproof-copies`, visibility **Public**, empty. In
   `gitlab/copies/parent/.gitlab-ci.yml`, replace `YOUR-NAMESPACE/scanproof-copies-private` with
   the private project's path, then push it to `main` and create `inaccessible` from it:

   ```bash
   cd ../parent
   sed -i 's#YOUR-NAMESPACE/scanproof-copies-private#<you>/scanproof-copies-private#' .gitlab-ci.yml   # or edit by hand
   git init -b main && git add . && git commit -m "scanproof copies contract (parent)"
   git push https://gitlab.com/<you>/scanproof-copies.git main
   git push https://gitlab.com/<you>/scanproof-copies.git main:inaccessible
   ```

3. **Public pipelines.** In `scanproof-copies`: *Settings > General > Visibility*: CI/CD
   **Everyone with access**; *Settings > CI/CD > General pipelines*: **Public pipelines** on. Leave
   the private project private.

4. **Schedules.** In `scanproof-copies`, *Build > Pipeline schedules*: one weekly schedule for
   `main` and one for `inaccessible` (e.g. `0 4 * * 1`). Press **Play** on both once and wait
   until both pipelines are green; the `inaccessible` one must show `svc-private` passing.

5. **Check anonymous access** (no token): the public child jobs are readable, the private ones
   are not.

   ```bash
   P=$(printf %s '<you>/scanproof-copies' | sed 's#/#%2F#g')
   curl -s "https://gitlab.com/api/v4/projects/$P/pipelines?ref=inaccessible&status=success&per_page=1"
   curl -s "https://gitlab.com/api/v4/projects/$P/pipelines/<id>/bridges"   # svc-a, svc-b, svc-private
   curl -s -o /dev/null -w '%{http_code}\n' \
     "https://gitlab.com/api/v4/projects/<private project id>/pipelines/<child id>/jobs"   # 403 or 404
   ```

6. **Connect this repository.** In `scanproof-e2e` on GitHub: *Settings > Secrets and variables >
   Actions > Variables*, add `GITLAB_COPIES_PROJECT` = `<you>/scanproof-copies` (a variable, not a
   secret: the project is public). Then *Actions > copies-contract > Run workflow*. Until the
   variable exists, every run shows a `copies gitlab` warning and `verify-gitlab` is skipped, so
   scanproof#44 cannot be closed by a skipped job.

## Anonymous rate limits

The copies workflow serializes runs and waits 60 seconds between scenario verifications,
including the boundary between branches. Each scenario still invokes the real CLI and
checks its fresh report, provenance, exit code, exact codes and evaluated jobs. There is no
retry of a mismatched policy result into success. Shared anonymous GitLab quotas can still
be exhausted; pacing is mitigation, not validated evidence that the contract will pass.

Run [40657524861](https://github.com/abdelrahman-eladwy/scanproof-e2e/actions/runs/40657524861)
passed all five `main` scenarios and the first `inaccessible` scenario. Its saved report
`inaccessible-not-required.json` records `RATE_LIMITED` for **both** public children and the
private child. With no public jobs visible, `JOB_MAYBE_IN_UNREADABLE_PIPELINE` correctly
failed closed. The final scenario failed on root HTTP 429. This is separate from core #69's
unrelated-subtree precision defect. Keep #8 and core #44 open until all eight scenarios pass.
