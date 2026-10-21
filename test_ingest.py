# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for ingestion: the guard on article fetches (feeds supply the links,
so only http(s) URLs resolving to public addresses are fetched), the shared
matching and config loading, feed polling (a failure is not an empty feed;
a headline counts for matching), KEV ingestion, retagging the archive, and
enrich's summary telling a skipped or failed step from one that found nothing.
Nothing touches the real database or configs.

    .venv\\Scripts\\python.exe -m unittest -v test_ingest
"""
import json
import socket
import tempfile
import unittest
import urllib.error
from datetime import date, timedelta
from pathlib import Path
from unittest import mock

import feedparser

import db
import enrich
import extract
import ghsa
import ingest
import kev
import main


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

    def test_an_excluded_phrase_stops_a_term_matching_inside_it(self):
        watchlist = {"web": [{"term": "PHP", "exclude": ["PHP Jabbers", "css-js-php"]}], "cloud": ["AWS"]}
        self.assertEqual(extract.match_vendors("PHP Jabbers Booking Calendar", watchlist), [])
        self.assertEqual(extract.match_vendors("Custom css-js-php", watchlist), [])
        self.assertEqual(extract.match_vendors("PHP Group PHP", watchlist), [("web", "PHP")])
        # The exclusion blanks its own phrase, not the whole text: real PHP elsewhere still counts.
        self.assertEqual(extract.match_vendors("PHP Jabbers Booking ; PHP Group PHP on AWS", watchlist),
                         [("web", "PHP"), ("cloud", "AWS")])

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

    def test_only_critical_advisories_are_high_ticket(self):
        def adv(n, severity, score):
            return {"ghsa_id": f"GHSA-{n}", "html_url": f"https://github.com/advisories/GHSA-{n}",
                    "summary": f"Flaw {n}", "severity": severity, "cve_id": f"CVE-2026-{1000 + n}",
                    "cvss_severities": {"cvss_v3": {"score": score}}, "published_at": "2026-10-19T00:00:00Z"}
        advisories = [adv(1, "high", 7.5), adv(2, "critical", 8.8), adv(3, "high", 9.1), adv(4, "medium", None)]
        with mock.patch.object(ghsa, "fetch_advisories", return_value=advisories):
            ghsa.ingest_ghsa(self.conn)
        flagged = {r[0]: r[1] for r in self.conn.execute("SELECT guid, high_ticket FROM articles")}
        self.assertEqual(flagged, {"GHSA-1": 0, "GHSA-2": 1, "GHSA-3": 1, "GHSA-4": 0})


class FeedPolling(unittest.TestCase):
    setUp = KevIngest.setUp   # a fresh database and empty filters

    def poll(self, **fields):
        parsed = feedparser.FeedParserDict(entries=[], **fields)
        with mock.patch.object(ingest.feedparser, "parse", return_value=parsed):
            return ingest.ingest_source(self.conn, "Feed", "https://feed.example/rss")

    def test_a_failed_feed_is_reported_not_counted_as_empty(self):
        self.assertIn("timed out", self.poll(bozo=1, bozo_exception=urllib.error.URLError("timed out"))["error"])
        self.assertIn("HTTP 404", self.poll(status=404, bozo=0)["error"])

    def test_an_empty_feed_and_an_unchanged_one_are_not_failures(self):
        self.assertNotIn("error", self.poll(status=200, bozo=0))
        self.assertNotIn("error", self.poll(status=304))

    def test_a_headline_naming_a_watched_vendor_matches(self):
        entry = {"link": "https://news.example/1", "id": "1", "title": "Ivanti patches a gateway flaw",
                 "description": "The vendor shipped a fix."}
        parsed = feedparser.FeedParserDict(entries=[entry], status=200, bozo=0)
        with mock.patch.object(ingest.feedparser, "parse", return_value=parsed), \
                mock.patch.object(ingest, "_extract_from_entry", return_value=("The vendor shipped a fix.", [])), \
                mock.patch.object(extract, "load_filters", return_value=({"edge": ["Ivanti"]}, [], [])):
            ingest.ingest_source(self.conn, "Feed", "https://feed.example/rss")
        self.assertEqual(self.conn.execute("SELECT vendor_term FROM vendor_matches").fetchall()[0][0], "Ivanti")


class Retag(unittest.TestCase):
    setUp = KevIngest.setUp   # a fresh database and empty filters

    def match_with(self, watchlist, tags=()):
        return lambda text: (extract.match_vendors(text, watchlist), extract.match_named(text, list(tags)), [])

    def test_stored_articles_are_rematched_and_a_dry_run_writes_nothing(self):
        source = db.upsert_source(self.conn, "Feed", "https://feed.example/")
        aid = db.insert_article(self.conn, source_id=source, guid="1", link="https://x.example/1",
                                title="Booking flaw", published_at=None, fetched_at="2026-10-21T00:00:00+00:00",
                                description="A flaw in PHP Jabbers Booking Calendar used by Group A",
                                full_text=None, high_ticket=False)
        db.insert_vendor_matches(self.conn, aid, [("web", "PHP")])            # matched before the exclusion
        now = self.match_with({"web": [{"term": "PHP", "exclude": ["PHP Jabbers"]}]}, [{"name": "Group A"}])

        dry = db.backfill_filter_matches(self.conn, now, write=False)
        self.assertEqual((dry["articles_changed"], dry["removed"]["vendor"], dry["added"]["entity"]), (1, 1, 1))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM vendor_matches").fetchone()[0], 1)

        db.backfill_filter_matches(self.conn, now)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM vendor_matches").fetchone()[0], 0)
        self.assertEqual([r[0] for r in self.conn.execute("SELECT entity_name FROM entity_matches")], ["Group A"])
        self.assertEqual(db.backfill_filter_matches(self.conn, now)["articles_changed"], 0)   # settled


class EnrichSummary(unittest.TestCase):
    setUp = KevIngest.setUp   # a fresh database and empty filters

    def test_a_skipped_step_reports_skipped_not_zero(self):
        s = enrich.enrich(self.conn, do_nvd=False, do_epss=False, do_kev=False, records_limit=0, do_coverage=False)
        self.assertEqual(s["skipped"], ["records", "coverage", "epss", "kev", "nvd"])
        for key in ("records_checked", "epss_updated", "kev_listed", "nvd_checked"):
            self.assertNotIn(key, s)
        self.assertEqual(main._count(s, "epss_updated", "epss"), "skipped")

    def test_a_failed_kev_fetch_reports_failed_not_zero(self):
        with mock.patch.object(enrich, "fetch_kev_catalog", return_value=None):
            s = enrich.enrich(self.conn, do_nvd=False, do_epss=False, records_limit=0, do_coverage=False)
        self.assertEqual(main._count(s, "kev_listed", "kev"), "fetch failed")


if __name__ == "__main__":
    unittest.main()
