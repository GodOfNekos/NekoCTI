# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for server.py's HTTP surface: the login gate, only the page's own
files are served, every response carries the security headers, and writes
need a session, the write header and a valid, size-capped body. The
database, password file and config writes all go to temp folders.

    .venv\\Scripts\\python.exe -m unittest -v test_server
"""
import http.client
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import auth
import db
import server

PASSWORD = "correct horse battery"


class Served(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        cls.patches = [mock.patch.object(db, "DB_PATH", tmp / "test.db"),
                       mock.patch.object(auth, "AUTH_FILE", tmp / "auth.json")]
        for p in cls.patches:
            p.start()
        db.init_db()
        auth.set_password(PASSWORD)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.cookie = cls.login_cookie()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        for p in cls.patches:
            p.stop()
        cls.tmp.cleanup()

    def setUp(self):
        auth._failures.clear()

    @classmethod
    def raw(cls, path, method="GET", body=None, headers=None):
        """One request, redirects not followed. Returns (status, headers, body)."""
        c = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, r.headers, data

    @classmethod
    def login_cookie(cls, password=PASSWORD):
        status, headers, _ = cls.raw("/api/login", "POST", json.dumps({"password": password}),
                                     {"X-NekoCTI": "1", "Content-Type": "application/json"})
        assert status == 200, status
        return headers["Set-Cookie"].split(";", 1)[0]

    def request(self, path, method="GET", body=None, headers=None, cookie=True):
        h = dict(headers or {})
        if cookie:
            h["Cookie"] = self.cookie if cookie is True else cookie
        return self.raw(path, method, body, h)


class Login(Served):
    def login(self, password, header=True):
        headers = {"Content-Type": "application/json", **({"X-NekoCTI": "1"} if header else {})}
        return self.raw("/api/login", "POST", json.dumps({"password": password}), headers)

    def test_everything_needs_a_session(self):
        status, headers, _ = self.request("/", cookie=False)
        self.assertEqual((status, headers["Location"]), (303, "/login"))
        self.assertEqual(self.request("/app.js", cookie=False)[0], 303)
        self.assertEqual(self.request("/api/articles", cookie=False)[0], 401)
        self.assertEqual(self.request("/api/watchlist", "PUT", b"{}", {"X-NekoCTI": "1"}, cookie=False)[0], 401)
        self.assertEqual(self.request("/api/ingest/run", "POST", b"", {"X-NekoCTI": "1"}, cookie=False)[0], 401)
        for forged in ("nekocti_session=forged", "nekocti_session=", "junk;;=="):
            self.assertEqual(self.request("/api/articles", cookie=forged)[0], 401, forged)

    def test_the_login_page_loads_without_one(self):
        for path in ("/login", "/login.js", "/style.css", "/fonts/ShareTechMono-Regular.ttf"):
            self.assertEqual(self.request(path, cookie=False)[0], 200, path)

    def test_the_right_password_gives_a_strict_session_cookie(self):
        status, headers, _ = self.login(PASSWORD)
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"]
        for flag in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/", f"Max-Age={auth.SESSION_SECONDS}"):
            self.assertIn(flag, cookie)
        self.assertEqual(self.request("/", cookie=cookie.split(";", 1)[0])[0], 200)

    def test_wrong_password_and_missing_header_are_refused(self):
        self.assertEqual(self.login("wrong password!")[0], 401)
        self.assertEqual(self.login(PASSWORD, header=False)[0], 403)
        self.assertEqual(self.raw("/api/login", "POST", b"[1]", {"X-NekoCTI": "1"})[0], 401)

    def test_five_wrong_passwords_lock_logins(self):
        for _ in range(auth.MAX_FAILURES):
            self.assertEqual(self.login("wrong password!")[0], 401)
        self.assertEqual(self.login(PASSWORD)[0], 429)
        auth._failures[:] = [t - auth.LOCKOUT_SECONDS for t in auth._failures]  # 15 minutes later
        self.assertEqual(self.login(PASSWORD)[0], 200)

    def test_logout_ends_the_session(self):
        cookie = self.login_cookie()
        self.assertEqual(self.request("/api/articles", cookie=cookie)[0], 200)
        status, headers, _ = self.request("/api/logout", "POST", b"", {"X-NekoCTI": "1"}, cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertEqual(self.request("/api/articles", cookie=cookie)[0], 401)

    def test_an_expired_session_is_refused(self):
        cookie = self.login_cookie()
        conn = sqlite3.connect(db.DB_PATH)
        conn.execute("UPDATE sessions SET expires_at = ?", (time.time() - 1,))
        conn.commit()
        conn.close()
        self.assertEqual(self.request("/api/articles", cookie=cookie)[0], 401)
        type(self).cookie = self.login_cookie()  # the shared session expired too

    def test_setting_the_password_ends_every_session(self):
        cookie = self.login_cookie()
        auth.set_password(PASSWORD)
        self.assertEqual(self.request("/api/articles", cookie=cookie)[0], 401)
        type(self).cookie = self.login_cookie()
        with self.assertRaises(ValueError):
            auth.set_password("short")

    def test_no_password_set_says_so(self):
        with mock.patch.object(auth, "AUTH_FILE", Path(self.tmp.name) / "empty.json"):
            (Path(self.tmp.name) / "empty.json").write_text("")
            self.assertEqual(self.login(PASSWORD)[0], 503)


class StaticFiles(Served):
    def test_the_page_and_its_assets_are_served(self):
        for path, ctype in (("/", "text/html"), ("/index.html", "text/html"), ("/style.css", "text/css"),
                            ("/app.js", "application/javascript"), ("/fonts/ShareTechMono-Regular.ttf", "font/ttf"),
                            ("/login", "text/html"), ("/login.js", "application/javascript")):
            code, headers, _ = self.request(path)
            self.assertEqual(code, 200, path)
            self.assertTrue(headers["Content-Type"].startswith(ctype), (path, headers["Content-Type"]))

    def test_nothing_else_is(self):
        for path in ("/data/tailscale-state/tailscaled.state", "/data/tailscale-state/certs/acme-account.key.pem",
                     "/data/nekocti.db", "/nekocti.db", "/watchlist.json", "/auth.json", "/data/auth.json",
                     "/server.py", "/pyproject.toml", "/.env", "/fonts/", "/fonts/../server.py", "/%2e%2e/server.py",
                     "/_ref_fonts/monofonto.otf"):
            self.assertEqual(self.request(path)[0], 404, path)
            self.assertNotEqual(self.request(path, cookie=False)[0], 200, path)

    def test_every_response_carries_the_security_headers(self):
        for path, cookie in (("/", True), ("/app.js", True), ("/nekocti.db", True), ("/", False), ("/login", False)):
            _, headers, _ = self.request(path, cookie=cookie)
            self.assertIn("script-src 'self'", headers["Content-Security-Policy"], path)
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"], path)
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff", path)
            self.assertEqual(headers["Referrer-Policy"], "no-referrer", path)


class Writes(Served):
    GOOD = {"vendors": {"cloud": ["Microsoft", "AWS"]}}

    def setUp(self):
        super().setUp()
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

    def test_a_term_with_exclusions_is_written(self):
        good = {"vendors": {"web": ["AWS", {"term": "PHP", "exclude": ["PHP Jabbers"]}, {"term": "Okta"}]}}
        self.assertEqual(self.put("/api/watchlist", good), 200)
        self.assertEqual(json.loads((self.dir / "watchlist.json").read_text()), good)

    def test_writes_without_the_header_are_refused(self):
        self.assertEqual(self.put("/api/watchlist", self.GOOD, header=False), 403)
        self.assertEqual(self.request("/api/ingest/run", "POST", b"")[0], 403)
        self.assertFalse((self.dir / "watchlist.json").exists())

    def test_bad_shapes_and_junk_are_refused(self):
        for path, bad in (("/api/watchlist", {"vendors": "x"}), ("/api/watchlist", {"vendors": {"c": [1]}}),
                          ("/api/watchlist", {"vendors": {}, "extra": 1}), ("/api/tags", {"entities": [{"name": ""}]}),
                          ("/api/watchlist", {"vendors": {"c": [{"term": ""}]}}),
                          ("/api/watchlist", {"vendors": {"c": [{"term": "PHP", "exclude": "PHP Jabbers"}]}}),
                          ("/api/watchlist", {"vendors": {"c": [{"term": "PHP", "exclude": [""]}]}}),
                          ("/api/watchlist", {"vendors": {"c": [{"term": "PHP", "html": "<b>"}]}}),
                          ("/api/tags", {"entities": [{"name": "x", "aliases": "y"}]}),
                          ("/api/campaigns", {"campaigns": [{"name": "x", "html": "<b>"}]}),
                          ("/api/tags", b"not json"), ("/api/tags", [1, 2])):
            self.assertEqual(self.put(path, bad), 400, (path, bad))
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_oversized_bodies_are_refused(self):
        huge = {"vendors": {"c": ["x" * (server.MAX_CONFIG_BYTES + 1)]}}
        self.assertEqual(self.put("/api/watchlist", huge), 413)


class SessionCookie(unittest.TestCase):
    """Only a token-shaped value can reach the Set-Cookie header, so nothing
    can split the response or set cookie attributes (code scanning, October 2026)."""

    def test_a_real_token_and_the_logout_value_are_written(self):
        token = auth.secrets.token_urlsafe(32)
        self.assertTrue(server.Handler._cookie(token, 60).startswith(f"{server.SESSION_COOKIE}={token}; HttpOnly"))
        self.assertIn("Max-Age=0", server.Handler._cookie("", 0))

    def test_anything_else_is_refused(self):
        for bad in ("abc\r\nSet-Cookie: x=1", "abc; Domain=evil.example", "a=b", "abc def", "abc\n"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                server.Handler._cookie(bad, 60)


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


class FreshInstall(unittest.TestCase):
    """A new container's entrypoint creates empty config files. Empty means
    "nothing configured yet", the same as missing, never a crash."""

    def test_empty_config_files_read_as_empty(self):
        import extract
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for name in ("watchlist.json", "tags.json", "campaigns.json"):
                (d / name).write_text("", encoding="utf-8")
            with mock.patch.object(extract, "WATCHLIST_PATH", d / "watchlist.json"), \
                 mock.patch.object(extract, "TAGS_PATH", d / "tags.json"), \
                 mock.patch.object(extract, "CAMPAIGNS_PATH", d / "campaigns.json"):
                self.assertEqual(extract.load_filters(), ({}, [], []))
            with mock.patch.object(server, "HERE", d):
                self.assertEqual(server.read_config("/api/watchlist"), {"vendors": {}})
                self.assertEqual(server.read_config("/api/tags"), {"entities": []})
