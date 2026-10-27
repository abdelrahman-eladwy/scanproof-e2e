# Scan targets

Deliberately vulnerable inputs that the workflows scan to produce real reports. **Never deploy,
run or apply them**, and never let a dependency bot update them.

| Folder | Scanned by |
|---|---|
| `sample-app/` | Semgrep (native JSON, SARIF), GitLab's Semgrep analyzer |
| `node/` | Trivy filesystem, OSV-Scanner, GitLab dependency scanning (lodash 4.17.15 has known CVEs) |
| `terraform/` | Checkov (IaC) |
| `kubernetes/` | Kubescape (privileged container, unpinned image) |

Secret-detection reports are produced from a **randomly generated fake token at run time**, with
scanner redaction on, so no secret-looking string is ever committed.
