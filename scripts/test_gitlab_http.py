"""Offline tests for gitlab_http.py: the token goes only to gitlab.com and never on a redirect.

Run: python -m unittest scripts/test_gitlab_http.py
"""

from __future__ import annotations

import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import gitlab_http  # noqa: E402

API = "https://gitlab.com/api/v4/projects/1/jobs/2/artifacts/gl-sast-report.json"


class Transport(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.dict(os.environ, {"GITLAB_TOKEN": "glpat-secret"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_token_is_an_unredirected_header(self) -> None:
        req = gitlab_http.request(API, {"User-Agent": "x"})
        self.assertEqual(req.unredirected_hdrs.get("Authorization"), "Bearer glpat-secret")
        self.assertNotIn("Authorization", req.headers)
        self.assertNotIn("glpat-secret", req.full_url)

    def test_no_token_sends_no_authorization(self) -> None:
        with mock.patch.dict(os.environ, {"GITLAB_TOKEN": " "}):
            req = gitlab_http.request(API, {})
        self.assertIsNone(req.get_header("Authorization"))

    def test_only_gitlab_com_over_https(self) -> None:
        for url in ("http://gitlab.com/api/v4/x", "https://gitlab.com.evil.example/x",
                    "https://evil.example/https://gitlab.com/"):  # fmt: skip
            with self.assertRaises(ValueError):
                gitlab_http.request(url, {})

    def test_redirect_to_storage_does_not_carry_the_token(self) -> None:
        handler = gitlab_http._HttpsOnlyRedirects()
        req = gitlab_http.request(API, {"User-Agent": "x"})
        new = handler.redirect_request(
            req, None, 302, "Found", {}, "https://storage.googleapis.com/bucket/report?sig=1"
        )
        self.assertIsNone(new.get_header("Authorization"))
        self.assertEqual(new.get_header("User-agent"), "x")

    def test_redirect_to_http_is_refused(self) -> None:
        handler = gitlab_http._HttpsOnlyRedirects()
        req = gitlab_http.request(API, {})
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(req, None, 302, "Found", {}, "http://gitlab.com/x")

    def test_opener_uses_the_https_only_handler(self) -> None:
        kinds = [type(h) for h in gitlab_http._OPENER.handlers]
        self.assertIn(gitlab_http._HttpsOnlyRedirects, kinds)
        self.assertNotIn(gitlab_http.urllib.request.HTTPRedirectHandler, kinds)


if __name__ == "__main__":
    unittest.main()
