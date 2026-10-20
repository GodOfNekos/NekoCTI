# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the priority score (priority.py): each rule's band, severity
alone stopping at MEDIUM, the watchlist lift, ageing claims, roundups, and
high_ticket following the band in both directions. Nothing touches the real
database or the network.

    .venv\\Scripts\\python.exe -m unittest -v test_priority
"""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import db
import priority as p


def band(**facts):
    return p.score_cve(facts)[1]


class CveRules(unittest.TestCase):
    def test_severity_alone_stops_at_medium(self):
        self.assertEqual(band(cvss=10.0, cvss_source="CNA"), "MEDIUM")
        self.assertEqual(band(cvss=7.5), "LOW")
        self.assertEqual(band(), "NONE")

    def test_exploitation_and_exploit_evidence(self):
        self.assertEqual(band(kev=True, kev_date="2026-10-01"), "CRITICAL")
        self.assertEqual(band(ssvc_exploitation="active"), "CRITICAL")
        self.assertEqual(band(reports=2, last_report_days=3), "HIGH")
        self.assertEqual(band(metasploit=True), "HIGH")
        self.assertEqual(band(epss_percentile=0.97), "HIGH")
        self.assertEqual(band(nuclei=True), "MEDIUM")
        self.assertEqual(band(poc_repo=True), "MEDIUM")
        self.assertEqual(band(ssvc_exploitation="poc"), "MEDIUM")
        self.assertEqual(band(sources_7d=3), "MEDIUM")
        self.assertEqual(band(poc_mentioned=True), "LOW")

    def test_an_old_claim_drops_a_band_unless_kev_confirms_it(self):
        self.assertEqual(band(reports=1, last_report_days=45), "MEDIUM")
        self.assertEqual(band(reports=1, last_report_days=45, kev=True), "CRITICAL")

    def test_the_watchlist_lifts_one_band(self):
        self.assertEqual(band(cvss=9.8, watch_terms=["Fortinet"]), "HIGH")
        self.assertEqual(band(watch_terms=["Fortinet"]), "LOW")
        self.assertEqual(band(kev=True, watch_terms=["Fortinet"]), "CRITICAL")

    def test_other_rules_nudge_the_score_but_never_cross_a_band(self):
        alone = p.score_cve({"metasploit": True})[0]
        stacked, b, why = p.score_cve({"metasploit": True, "nuclei": True, "poc_repo": True, "cvss": 9.8,
                                       "sources_7d": 5, "ssvc_exploitation": "poc", "epss_percentile": 0.99})
        self.assertEqual(b, "HIGH")
        self.assertTrue(alone < stacked < 400)
        self.assertEqual(why[0].split()[0], "Metasploit")       # strongest rule first


class ArticleRules(unittest.TestCase):
    def test_an_article_takes_its_strongest_cve(self):
        kev = (*p.score_cve({"kev": True}), "CVE-2026-0001")
        low = (*p.score_cve({"cvss": 7.0}), "CVE-2026-0002")
        self.assertEqual(p.score_article([low, kev], n_cves=2)[1], "CRITICAL")

    def test_a_roundup_is_capped_at_medium_from_its_cves(self):
        kev = (*p.score_cve({"kev": True}), "CVE-2026-0001")
        score, b, why = p.score_article([kev], n_cves=40)
        self.assertEqual(b, "MEDIUM")
        self.assertIn("roundup naming 40 CVEs", why[0])

    def test_a_cve_mentioned_in_passing_counts_at_medium_at_most(self):
        kev = (*p.score_cve({"kev": True}), "CVE-2026-0001")
        self.assertEqual(p.score_article([kev], n_cves=1, subjects=set())[1], "MEDIUM")
        self.assertIn("in passing", p.score_article([kev], n_cves=1, subjects=set())[2][0])
        self.assertEqual(p.score_article([kev], n_cves=1, subjects={"CVE-2026-0001"})[1], "CRITICAL")

    def test_what_makes_a_cve_the_subject(self):
        names = ["Oracle Corporation PeopleSoft Enterprise PeopleTools"]
        self.assertTrue(p.names_subject("CVE-1", "Attackers exploit Oracle PeopleSoft flaw", names))
        self.assertFalse(p.names_subject("CVE-1", "Police arrest hacking suspect", names))
        self.assertFalse(p.names_subject("CVE-1", "Enterprise security weekly", names))   # generic words only
        self.assertTrue(p.names_subject("CVE-2026-1234", "Patch CVE-2026-1234 now", []))
        self.assertTrue(p.names_subject("CVE-1", "anything", [], structured=True))

    def test_what_the_article_itself_says(self):
        self.assertEqual(p.score_article([], n_cves=0, title_claim=True)[1], "HIGH")
        self.assertEqual(p.score_article([], n_cves=0, tracked=["Group A"])[1], "HIGH")
        self.assertEqual(p.score_article([], n_cves=0, breach=True)[1], "MEDIUM")
        self.assertEqual(p.score_article([], n_cves=0)[1], "NONE")


class Recompute(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        q = mock.patch.object(db, "DB_PATH", Path(tmp.name) / "t.db")
        q.start()
        self.addCleanup(q.stop)
        r = mock.patch.object(p.extract, "load_filters", return_value=({}, [], []))
        r.start()
        self.addCleanup(r.stop)
        db.init_db()
        self.conn = db.connect()
        self.addCleanup(self.conn.close)
        self.source = db.upsert_source(self.conn, "Feed", "https://feed.example/")
        self.n = 0

    def article(self, cve, high_ticket, source=None):
        self.n += 1
        aid = db.insert_article(self.conn, source_id=source or self.source, guid=str(self.n), link=f"https://x.example/{self.n}",
                                title=f"Advisory {self.n}", published_at=None, fetched_at="2026-10-19T00:00:00+00:00",
                                description="d", full_text=None, high_ticket=high_ticket)
        db.insert_cve_mentions(self.conn, aid, [(cve, None)])
        return aid

    def test_high_ticket_follows_the_band_both_ways(self):
        severe = self.article("CVE-2026-1000", high_ticket=True)    # flagged at ingest on severity alone
        kev_source = db.upsert_source(self.conn, "CISA KEV", "https://kev.example/")
        exploited = self.article("CVE-2026-1001", high_ticket=False, source=kev_source)   # a one-CVE advisory
        db.record_cve_record(self.conn, "CVE-2026-1000", {"base_score": 9.8, "score_source": "CNA", "affected": []})
        db._upsert_cve_score(self.conn, "CVE-2026-1001", {"kev_listed": 1, "kev_date_added": "2026-10-18"})
        self.conn.commit()
        s = p.recompute(self.conn)
        rows = {r["id"]: r for r in self.conn.execute("SELECT id, high_ticket, priority_band FROM articles")}
        self.assertEqual((rows[severe]["high_ticket"], rows[severe]["priority_band"]), (0, "MEDIUM"))
        self.assertEqual((rows[exploited]["high_ticket"], rows[exploited]["priority_band"]), (1, "CRITICAL"))
        self.assertEqual(s["high_ticket_now"], 1)


if __name__ == "__main__":
    unittest.main()
