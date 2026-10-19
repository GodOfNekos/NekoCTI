# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the CVE record (cverecord.py): parsing a real record's shape,
which source a score comes from, failures that mustn't be recorded as
answers, and the CVE-to-vendor link coming from the record rather than from
a roundup article. Nothing touches the real database or the network.

    .venv\\Scripts\\python.exe -m unittest -v test_cverecord
"""
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import cverecord
import db

# Trimmed from the real cvelistV5 record for CVE-2024-3400, read 19 October 2026.
REAL = {
    "cveMetadata": {"cveId": "CVE-2024-3400", "state": "PUBLISHED", "datePublished": "2024-04-12T06:52:35.000Z"},
    "containers": {
        "cna": {
            "metrics": [{"cvssV3_1": {"baseScore": 10, "baseSeverity": "CRITICAL", "version": "3.1",
                                      "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
                         "format": "CVSS"}],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-77", "type": "CWE"}]},
                             {"descriptions": [{"cweId": "CWE-20", "type": "CWE"}]}],
            "affected": [{"vendor": "Palo Alto Networks", "product": "PAN-OS"},
                         {"vendor": "Palo Alto Networks", "product": "Cloud NGFW"},
                         {"vendor": "Palo Alto Networks", "product": "PAN-OS"}],
        },
        "adp": [{"providerMetadata": {"shortName": "CISA-ADP"},
                 "metrics": [{"other": {"type": "ssvc", "content": {"options": [
                     {"Exploitation": "active"}, {"Automatable": "yes"}, {"Technical Impact": "total"}]}}},
                     {"other": {"type": "kev", "content": {"dateAdded": "2024-04-12"}}}]}],
    },
}


class Parsing(unittest.TestCase):
    def test_record_urls_follow_the_thousands_block(self):
        self.assertEqual(cverecord.record_url("CVE-2024-3400"), f"{cverecord.BASE_URL}/2024/3xxx/CVE-2024-3400.json")
        self.assertEqual(cverecord.record_url("CVE-2026-111472"), f"{cverecord.BASE_URL}/2026/111xxx/CVE-2026-111472.json")
        self.assertIsNone(cverecord.record_url("CVE-26-1"))

    def test_a_real_record(self):
        p = cverecord.parse_record(REAL)
        self.assertEqual((p["base_score"], p["severity"], p["version"], p["score_source"]), (10, "CRITICAL", "3.1", "CNA"))
        self.assertEqual((p["ssvc_exploitation"], p["ssvc_automatable"], p["ssvc_technical_impact"]), ("active", "yes", "total"))
        self.assertEqual(p["cwes"], ["CWE-20", "CWE-77"])
        self.assertEqual(p["affected"], [("Palo Alto Networks", "PAN-OS"), ("Palo Alto Networks", "Cloud NGFW")])
        self.assertEqual(p["state"], "PUBLISHED")

    def test_cisa_score_when_the_cna_gave_none_and_newest_version_first(self):
        rec = {"containers": {
            "cna": {"metrics": [], "affected": [{"vendor": "n/a", "product": "n/a"}, {"vendor": "Acme", "product": "N/A"}]},
            "adp": [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [
                {"cvssV3_1": {"baseScore": 7.5, "version": "3.1"}},
                {"cvssV4_0": {"baseScore": 8.7, "version": "4.0"}}]}]}}
        p = cverecord.parse_record(rec)
        self.assertEqual((p["base_score"], p["version"], p["score_source"]), (8.7, "4.0", "CISA-ADP"))
        self.assertEqual(p["affected"], [("Acme", "")])

    def test_a_rejected_record_has_no_score(self):
        p = cverecord.parse_record({"cveMetadata": {"state": "REJECTED"}, "containers": {"cna": {}}})
        self.assertEqual((p["state"], p["base_score"], p["score_source"], p["affected"]), ("REJECTED", None, None, []))


class Fetching(unittest.TestCase):
    def _raising(self, exc):
        return mock.patch.object(cverecord.enrich, "get_json", side_effect=exc)

    def test_a_404_is_an_answer_and_other_failures_are_not(self):
        with self._raising(urllib.error.HTTPError("u", 404, "nf", {}, None)):
            self.assertEqual(cverecord.fetch_record("CVE-2026-0001"), (None, True))
        with self._raising(urllib.error.HTTPError("u", 503, "x", {}, None)):
            self.assertEqual(cverecord.fetch_record("CVE-2026-0001"), (None, False))
        with self._raising(TimeoutError()):
            self.assertEqual(cverecord.fetch_record("CVE-2026-0001"), (None, False))


class WithDatabase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = mock.patch.object(db, "DB_PATH", Path(tmp.name) / "t.db")
        p.start()
        self.addCleanup(p.stop)
        db.init_db()
        self.conn = db.connect()
        self.addCleanup(self.conn.close)
        self.source = db.upsert_source(self.conn, "Feed", "https://feed.example/")
        self.n = 0

    def article(self, cves, vendor_terms=(), title=None):
        self.n += 1
        aid = db.insert_article(self.conn, source_id=self.source, guid=str(self.n), link=f"https://x.example/{self.n}",
                                title=title or f"t{self.n}", published_at=None, fetched_at="2026-10-19T00:00:00+00:00",
                                description=f"d{self.n}", full_text=None, high_ticket=False)
        db.insert_cve_mentions(self.conn, aid, [(c, None) for c in cves])
        db.insert_vendor_matches(self.conn, aid, [("cat", t) for t in vendor_terms])
        return aid

    def test_the_vendor_link_comes_from_the_record_not_a_roundup(self):
        watchlist = {"edge": ["Palo Alto"], "cloud": ["Microsoft"]}
        roundup = [f"CVE-2026-{1000 + i}" for i in range(60)]
        self.article(roundup, ["Microsoft"], title="Microsoft weekly roundup")   # names 60 CVEs
        self.article(["CVE-2026-1001"], ["Microsoft", "Palo Alto"], title="Microsoft fixes a flaw")
        self.article(["CVE-2026-1002"], ["Microsoft", "Palo Alto"], title="Week 41 in security")  # a small weekly report
        db.record_cve_record(self.conn, "CVE-2026-1000", cverecord.parse_record(REAL))
        terms = cverecord.watchlist_terms(self.conn, ["CVE-2026-1000", "CVE-2026-1001", "CVE-2026-1002"], watchlist)
        self.assertEqual(terms, {"CVE-2026-1000": ["Palo Alto"],   # its record says Palo Alto, not Microsoft
                                 "CVE-2026-1001": ["Microsoft"]})  # no record: a small article's title counts,
        # neither a roundup nor a weekly report's body ties 1002 to anything

    def test_refresh_records_answers_skips_failures_and_never_rereads_rejected(self):
        self.article(["CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2003"])
        answers = {"CVE-2026-2001": (REAL, True), "CVE-2026-2002": (None, True), "CVE-2026-2003": (None, False)}
        with mock.patch.object(cverecord, "fetch_record", side_effect=lambda c: answers[c]):
            s = cverecord.refresh(self.conn, limit=10)
        self.assertEqual((s["records_checked"], s["records_scored"], s["records_failed"]), (2, 1, 1))
        rows = {r["cve_id"]: r for r in self.conn.execute("SELECT * FROM cve_scores")}
        self.assertEqual((rows["CVE-2026-2001"]["rec_base_score"], rows["CVE-2026-2002"]["rec_state"]), (10, "MISSING"))
        self.assertNotIn("CVE-2026-2003", rows)                  # a failed lookup isn't an answer
        self.conn.execute("UPDATE cve_scores SET rec_checked_at = '2000-01-01', rec_state = 'REJECTED', "
                          "rec_base_score = NULL WHERE cve_id = 'CVE-2026-2001'")
        self.assertNotIn("CVE-2026-2001", db.cves_needing_record(self.conn, 7, 90, 10))


if __name__ == "__main__":
    unittest.main()
