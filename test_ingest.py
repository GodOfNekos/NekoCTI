# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for ingestion: the guard on article fetches (feeds supply the links,
so only http(s) URLs resolving to public addresses are fetched), the shared
matching and config loading, and KEV ingestion through the shared fetcher.
Nothing touches the real database or configs.

    .venv\\Scripts\\python.exe -m unittest -v test_ingest
"""
import json
import socket
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest import mock

import db
import extract
import ingest
import kev


def resolving_to(*ips):
    return lambda host, port, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]


class PublicUrlsOnly(unittest.TestCase):
    def test_public_http_urls_pass(self):
        self.assertTrue(ingest.is_public_http_url("https://news.example/a", resolving_to("93.184.216.34")))
        self.assertTrue(ingest.is_public_http_url("http://news.example/a", resolving_to("2606:4700::1")))

    def test_private_loopback_and_tailnet_addresses_are_refused(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.17.0.1", "169.254.169.254",
                   "100.100.100.100", "::1", "fd7a:115c:a1e0::1"):
            self.assertFalse(ingest.is_public_http_url("https://news.example/a", resolving_to(ip)), ip)

    def test_one_private_address_among_public_ones_is_refused(self):
        self.assertFalse(ingest.is_public_http_url("https://x.example/", resolving_to("93.184.216.34", "10.0.0.1")))

    def test_other_schemes_and_unresolvable_hosts_are_refused(self):
        for url in ("file:///etc/passwd", "ftp://x.example/", "javascript:alert(1)", "https:///nohost", ""):
            self.assertFalse(ingest.is_public_http_url(url, resolving_to("93.184.216.34")), url)

        def fails(*a, **k):
            raise socket.gaierror
        self.assertFalse(ingest.is_public_http_url("https://nowhere.invalid/", fails))

    def test_the_real_resolver_refuses_localhost(self):
        self.assertFalse(ingest.is_public_http_url("http://localhost:8778/data/nekocti.db"))

    def test_fetch_full_text_never_fetches_a_refused_url(self):
        with mock.patch.object(ingest.trafilatura, "fetch_url") as fetch:
            self.assertEqual(ingest.fetch_full_text("http://127.0.0.1:11434/api/tags"), (None, []))
        fetch.assert_not_called()


class Matching(unittest.TestCase):
    def test_names_match_by_name_or_alias_whole_word_any_case(self):
        items = [{"name": "Group A", "aliases": ["APT-Zero"]}, {"name": "Campaign B"}]
        self.assertEqual(extract.match_named("seen: apt-zero and CAMPAIGN B", items), ["Group A", "Campaign B"])
        self.assertEqual(extract.match_named("apt-zeroes", items), [])

    def test_filters_load_with_defaults_for_missing_files(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "w.json").write_text(json.dumps({"vendors": {"cloud": ["AWS"]}}))
            with mock.patch.object(extract, "WATCHLIST_PATH", d / "w.json"), \
                    mock.patch.object(extract, "TAGS_PATH", d / "none.json"), \
                    mock.patch.object(extract, "CAMPAIGNS_PATH", d / "none2.json"):
                self.assertEqual(extract.load_filters(), ({"cloud": ["AWS"]}, [], []))


class KevIngest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for target, name, value in ((db, "DB_PATH", Path(tmp.name) / "t.db"),
                                    (extract, "load_filters", lambda: ({}, [], []))):
            p = mock.patch.object(target, name, value)
            p.start()
            self.addCleanup(p.stop)
        db.init_db()
        self.conn = db.connect()
        self.addCleanup(self.conn.close)

    def test_recent_entries_become_high_ticket_articles_once(self):
        today, old = date.today().isoformat(), (date.today() - timedelta(days=90)).isoformat()
        catalog = {"CVE-2026-0001": {"cveID": "CVE-2026-0001", "dateAdded": today, "vulnerabilityName": "New flaw"},
                   "CVE-2020-0002": {"cveID": "CVE-2020-0002", "dateAdded": old, "vulnerabilityName": "Old flaw"}}
        with mock.patch.object(kev.enrich, "fetch_kev_catalog", return_value=catalog):
            first = kev.ingest_kev(self.conn)
            again = kev.ingest_kev(self.conn)
        self.assertEqual((first["new"], first["high_ticket"], again["new"]), (1, 1, 0))
        self.assertEqual([r[0] for r in self.conn.execute("SELECT cve_id FROM cve_mentions")], ["CVE-2026-0001"])

    def test_a_failed_fetch_is_reported_not_raised(self):
        with mock.patch.object(kev.enrich, "fetch_kev_catalog", return_value=None):
            self.assertIn("error", kev.ingest_kev(self.conn))


if __name__ == "__main__":
    unittest.main()
