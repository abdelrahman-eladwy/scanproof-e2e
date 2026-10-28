# Temporary live contract trigger — e2e issue #16

This fixture-only branch is intentionally disposable and tests the
`github-contract` workflow against ScanProof core `main` after the fix for #90.

Acceptance requires a successful first attempt and a *self-verify-only* rerun
which cannot treat inherited masked scan jobs as VERIFIED. This file carries
no secrets and does not modify any production branch or deployment protection.
