# GitLab copies contract: setup

The GitLab half of [`copies-contract`](../.github/workflows/copies-contract.yml) checks ScanProof's
copy completeness ([scanproof#65](https://github.com/abdelrahman-eladwy/scanproof/issues/65)) on
**real** gitlab.com child pipelines. It needs two GitLab projects that only the maintainer can
create. They are read with a **read-only token of a separate account** that is not a member of
the private project (step 6). Anonymous reads stopped being enough on 19 October 2026, when
gitlab.com limited unauthenticated API traffic to 60 requests per hour per IP; one contract run
needs about 66.

| Project | Visibility | Contents |
|---|---|---|
| `scanproof-copies` | **Public** | [`gitlab/copies/parent/`](../gitlab/copies/parent/) |
| `scanproof-copies-private` | **Private** | [`gitlab/copies/private/`](../gitlab/copies/private/) |

## What it proves

| Branch of `scanproof-copies` | Pipeline | Scenarios ([main](../policies/copies/gitlab-main-scenarios.json), [inaccessible](../policies/copies/gitlab-inaccessible-scenarios.json)) |
|---|---|---|
| `main` | `svc-a > copy-sast`, `svc-b > copy-sast` | both declared: exit 0 · `svc-c` declared (no such trigger, i.e. removed): exit 1 `REQUIRED_COPY_ABSENT` · production without `copies`: exit 2 `COPIES_UNDECLARED` · production with `copies`: exit 0 · compatible without `copies`: exit 0 + warning |
| `inaccessible` | the same, plus `svc-private`, a child in the private project (unreadable to the token's account) | `svc-private` declared: exit 2 `JOB_MAYBE_IN_UNREADABLE_PIPELINE` (unknown, **not** absent) · only `svc-a`, `svc-b` declared: exit 0 + "could not be read" warning · production without `copies`: exit 2 |

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

5. **Check public access** (a few anonymous requests are fine here): the public child jobs are readable, the private ones
   are not.

   ```bash
   P=$(printf %s '<you>/scanproof-copies' | sed 's#/#%2F#g')
   curl -s "https://gitlab.com/api/v4/projects/$P/pipelines?ref=inaccessible&status=success&per_page=1"
   curl -s "https://gitlab.com/api/v4/projects/$P/pipelines/<id>/bridges"   # svc-a, svc-b, svc-private
   curl -s -o /dev/null -w '%{http_code}\n' \
     "https://gitlab.com/api/v4/projects/<private project id>/pipelines/<child id>/jobs"   # 403 or 404
   ```

6. **Read-only token.** Register a separate gitlab.com account (not yours: yours can read the
   private project) and do not add it to the private project or its group. As that account:
   *Edit profile > Access tokens > Add new token*, scope **`read_api` only**, with an expiry.
   Check it can't see the private project (expect `404`):

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' -H "PRIVATE-TOKEN: <token>" \
     "https://gitlab.com/api/v4/projects/<url-encoded private project path>"
   ```

   The contract proves this on every run, twice: before the `inaccessible` scenarios it asks
   for the `svc-private` child's jobs with the token and requires HTTP 403 or 404 (a 200, or a
   429 / 5xx that proves nothing, fails the run); and each `inaccessible` scenario requires
   ScanProof to report `svc-private`, and only it, unreadable for `AUTH` or `NOT_FOUND`. The
   token is sent only to the gitlab.com API over https, never on a redirect (redirects are
   refused).

7. **Connect this repository.** In `scanproof-e2e` on GitHub: *Settings > Secrets and variables >
   Actions*: under **Secrets** add `GITLAB_COPIES_TOKEN` = the token; under **Variables** add
   `GITLAB_COPIES_PROJECT` = `<you>/scanproof-copies` (a variable, not a secret: the project is
   public). Then *Actions > copies-contract > Run workflow*. Without the secret, `verify-gitlab`
   fails with a message naming it. When the token expires, create a new one and replace the secret. Until the
   variable exists, every run shows a `copies gitlab` warning and `verify-gitlab` is skipped, so
   scanproof#44 cannot be closed by a skipped job.
