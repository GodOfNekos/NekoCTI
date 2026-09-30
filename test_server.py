"""Tests for server.py's static file serving: only the page's own files, never
the database, config, source or (in the container) data/ with the node's keys.

    .venv\\Scripts\\python.exe -m unittest -v test_server
"""
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import server


class StaticFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def status(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=5) as r:
                return r.status, r.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            return e.code, ""

    def test_the_page_and_its_assets_are_served(self):
        for path, ctype in (("/", "text/html"), ("/index.html", "text/html"), ("/style.css", "text/css"),
                            ("/app.js", "application/javascript"), ("/fonts/monofonto.otf", "font/otf")):
            code, got = self.status(path)
            self.assertEqual(code, 200, path)
            self.assertTrue(got.startswith(ctype), (path, got))

    def test_nothing_else_is(self):
        for path in ("/data/tailscale-state/tailscaled.state", "/data/tailscale-state/certs/acme-account.key.pem",
                     "/data/nekocti.db", "/nekocti.db", "/watchlist.json", "/server.py", "/pyproject.toml",
                     "/.env", "/fonts/", "/fonts/../server.py", "/%2e%2e/server.py", "/_ref_fonts/monofonto.otf"):
            self.assertEqual(self.status(path)[0], 404, path)


if __name__ == "__main__":
    unittest.main()
