"""Tests for server.py's HTTP surface: only the page's own files are served,
every response carries the security headers, and writes need the write
header and a valid, size-capped body. Config writes go to a temp folder.

    .venv\\Scripts\\python.exe -m unittest -v test_server
"""
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import server


class Served(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, path, method="GET", body=None, headers=None):
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()


class StaticFiles(Served):
    def test_the_page_and_its_assets_are_served(self):
        for path, ctype in (("/", "text/html"), ("/index.html", "text/html"), ("/style.css", "text/css"),
                            ("/app.js", "application/javascript"), ("/fonts/monofonto.otf", "font/otf")):
            code, headers, _ = self.request(path)
            self.assertEqual(code, 200, path)
            self.assertTrue(headers["Content-Type"].startswith(ctype), (path, headers["Content-Type"]))

    def test_nothing_else_is(self):
        for path in ("/data/tailscale-state/tailscaled.state", "/data/tailscale-state/certs/acme-account.key.pem",
                     "/data/nekocti.db", "/nekocti.db", "/watchlist.json", "/server.py", "/pyproject.toml",
                     "/.env", "/fonts/", "/fonts/../server.py", "/%2e%2e/server.py", "/_ref_fonts/monofonto.otf"):
            self.assertEqual(self.request(path)[0], 404, path)

    def test_every_response_carries_the_security_headers(self):
        for path in ("/", "/app.js", "/nekocti.db"):
            _, headers, _ = self.request(path)
            self.assertIn("script-src 'self'", headers["Content-Security-Policy"], path)
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"], path)
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff", path)
            self.assertEqual(headers["Referrer-Policy"], "no-referrer", path)


class Writes(Served):
    GOOD = {"vendors": {"cloud": ["Microsoft", "AWS"]}}

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        patcher = mock.patch.object(server, "HERE", self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def put(self, path, data, header=True):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        return self.request(path, "PUT", body, {"X-NekoCTI": "1"} if header else {})[0]

    def test_a_valid_config_is_written(self):
        self.assertEqual(self.put("/api/watchlist", self.GOOD), 200)
        self.assertEqual(json.loads((self.dir / "watchlist.json").read_text()), self.GOOD)
        tags = {"entities": [{"name": "Group A", "aliases": ["A1"]}]}
        self.assertEqual(self.put("/api/tags", tags), 200)
        self.assertEqual(self.put("/api/campaigns", {"campaigns": [{"name": "Campaign A"}]}), 200)

    def test_writes_without_the_header_are_refused(self):
        self.assertEqual(self.put("/api/watchlist", self.GOOD, header=False), 403)
        self.assertEqual(self.request("/api/ingest/run", "POST", b"")[0], 403)
        self.assertFalse((self.dir / "watchlist.json").exists())

    def test_bad_shapes_and_junk_are_refused(self):
        for path, bad in (("/api/watchlist", {"vendors": "x"}), ("/api/watchlist", {"vendors": {"c": [1]}}),
                          ("/api/watchlist", {"vendors": {}, "extra": 1}), ("/api/tags", {"entities": [{"name": ""}]}),
                          ("/api/tags", {"entities": [{"name": "x", "aliases": "y"}]}),
                          ("/api/campaigns", {"campaigns": [{"name": "x", "html": "<b>"}]}),
                          ("/api/tags", b"not json"), ("/api/tags", [1, 2])):
            self.assertEqual(self.put(path, bad), 400, (path, bad))
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_oversized_bodies_are_refused(self):
        huge = {"vendors": {"c": ["x" * (server.MAX_CONFIG_BYTES + 1)]}}
        self.assertEqual(self.put("/api/watchlist", huge), 413)


class Urls(unittest.TestCase):
    def test_only_http_urls_survive_and_relative_ones_are_resolved(self):
        base = "https://news.example/2026/09/article"
        self.assertEqual(server._http_url("/img/a.png", base), "https://news.example/img/a.png")
        self.assertEqual(server._http_url("https://cdn.example/b.png", base), "https://cdn.example/b.png")
        for bad in ("javascript:alert(1)", "data:image/png;base64,AAAA", "", None):
            self.assertIsNone(server._http_url(bad, base), bad)
        self.assertIsNone(server._http_url("javascript:alert(1)"))


if __name__ == "__main__":
    unittest.main()
