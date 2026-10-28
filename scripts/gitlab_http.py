"""Token-aware, redirect-safe GETs to the gitlab.com API, for the contract collectors.

gitlab.com allows 60 unauthenticated API requests per hour per IP (since 2026-10-19), less than
one contract run needs, so the collectors authenticate with GITLAB_TOKEN: a read_api token of
an account with no project memberships (docs/gitlab-copies.md). Rules, the same as ScanProof's:

- requests go only to https://gitlab.com/;
- the token is an *unredirected* header: never copied onto a redirect, so it can't reach object
  storage or any other host an artifact download redirects to;
- redirects are followed only to https (never downgraded to http).

Stdlib only.
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request

ORIGIN = "https://gitlab.com/"


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.HTTPError(newurl, code, f"refused redirect to {newurl}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirects)


def token() -> str:
    return os.environ.get("GITLAB_TOKEN", "").strip()


def request(url: str, headers: dict[str, str]) -> urllib.request.Request:
    if not url.startswith(ORIGIN):
        raise ValueError(f"refusing non-gitlab.com URL: {url}")
    req = urllib.request.Request(url, headers=headers)
    if token():
        req.add_unredirected_header("Authorization", f"Bearer {token()}")
    return req


def urlopen(url: str, headers: dict[str, str], timeout: float = 30):
    """Like urllib.request.urlopen, under the rules above. Raises HTTPError as urllib does."""
    return _OPENER.open(request(url, headers), timeout=timeout)
