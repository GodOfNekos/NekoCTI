# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for detection and exploit coverage (coverage.py): reading CVE IDs
from the listings, keeping the old rows when a listing fails, re-reading at
most daily, and the exploit maturity ladder. Nothing touches the real
database or the network.

    .venv\\Scripts\\python.exe -m unittest -v test_coverage
"""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import coverage
import db

TREE = {"truncated": False, "tree": [
    {"type": "blob", "path": "http/cves/2024/CVE-2024-3400.yaml"},
    {"type": "blob", "path": "rules-emerging-threats/2024/Exploits/CVE-2024-3400/proc_creation_lnx_cve_2024_3400.yml"},
    {"type": "blob", "path": "deprecated/windows/CVE-2021-0001.yml"},
    {"type": "blob", "path": "http/cves/2024/CVE-2024-9999.md"},
    {"type": "tree", "path": "http/cves/2024"},
]}
MSF = {
    "exploit_linux/http/panos": {"type": "exploit", "fullname": "exploit/linux/http/panos", "path": "/modules/exploits/linux/http/panos.rb",
                                 "references": ["CVE-2024-3400", "URL-https://x.example"]},
    "auxiliary_scanner/panos": {"type": "auxiliary", "fullname": "auxiliary/scanner/panos", "path": "/modules/auxiliary/scanner/panos.rb",
                                "references": ["CVE-2024-0002"]},
}


class Listings(unittest.TestCase):
    def test_cve_ids_come_from_yaml_paths_and_deprecated_rules_are_skipped(self):
        with mock.patch.object(coverage.enrich, "get_json", return_value=TREE):
            out = coverage._from_tree("u", "https://base/")
        self.assertEqual(sorted(out), ["CVE-2024-3400"])
        self.assertEqual(len(out["CVE-2024-3400"]), 2)
        self.assertTrue(out["CVE-2024-3400"][0][1].startswith("https://base/"))

    def test_a_truncated_or_failed_listing_is_none(self):
        with mock.patch.object(coverage.enrich, "get_json", return_value={"truncated": True, "tree": []}):
            self.assertIsNone(coverage._from_tree("u", "b"))
        with mock.patch.object(coverage.enrich, "get_json", side_effect=TimeoutError()):
            self.assertIsNone(coverage._from_tree("u", "b"))
            self.assertIsNone(coverage._from_metasploit())

    def test_only_metasploit_exploit_modules_count(self):
        with mock.patch.object(coverage.enrich, "get_json", return_value=MSF):
            out = coverage._from_metasploit()
        self.assertEqual(list(out), ["CVE-2024-3400"])
        self.assertEqual(out["CVE-2024-3400"][0][0], "exploit/linux/http/panos")

    def test_the_maturity_ladder(self):
        m = coverage.exploit_maturity
        self.assertEqual(m(True, False, set(), False, False), "ATTACKED")
        self.assertEqual(m(False, True, {"sigma"}, True, False), "ATTACKED")
        self.assertEqual(m(False, False, {"nuclei"}, True, False), "FUNCTIONAL")
        self.assertEqual(m(False, False, {"sigma"}, False, True), "POC")
        self.assertEqual(m(False, False, {"sigma"}, False, False), "UNPROVEN")


class Refresh(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = mock.patch.object(db, "DB_PATH", Path(tmp.name) / "t.db")
        p.start()
        self.addCleanup(p.stop)
        db.init_db()
        self.conn = db.connect()
        self.addCleanup(self.conn.close)
        source = db.upsert_source(self.conn, "Feed", "https://feed.example/")
        aid = db.insert_article(self.conn, source_id=source, guid="1", link="https://x.example/1", title="t",
                                published_at=None, fetched_at="2026-10-19T00:00:00+00:00", description="d",
                                full_text=None, high_ticket=False)
        db.insert_cve_mentions(self.conn, aid, [("CVE-2024-3400", None)])

    def refresh(self, tree, msf, force=False):
        with mock.patch.object(coverage, "_from_tree", return_value=tree), \
                mock.patch.object(coverage, "_from_metasploit", return_value=msf):
            return coverage.refresh(self.conn, force=force)

    def kinds(self):
        return sorted(r["kind"] for r in db.get_cve_coverage(self.conn, ["CVE-2024-3400"]).get("CVE-2024-3400", []))

    def test_only_captured_cves_are_stored_and_a_fresh_listing_isnt_reread(self):
        listing = {"CVE-2024-3400": [("p", "https://l")], "CVE-1999-0001": [("q", "https://m")]}
        s = self.refresh(listing, {"CVE-2024-3400": [("exploit/x", "https://n")]})
        self.assertEqual(sorted(s["coverage_refreshed"]), ["metasploit", "nuclei", "sigma"])
        self.assertEqual(self.kinds(), ["metasploit", "nuclei", "sigma"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM cve_coverage WHERE cve_id = 'CVE-1999-0001'").fetchone()[0], 0)
        self.assertEqual(self.refresh({}, {})["coverage_refreshed"], [])   # fresh: nothing re-read

    def test_a_failed_listing_keeps_what_was_there(self):
        self.refresh({"CVE-2024-3400": [("p", "https://l")]}, {"CVE-2024-3400": [("exploit/x", "https://n")]})
        s = self.refresh(None, None, force=True)
        self.assertEqual(sorted(s["coverage_failed"]), ["metasploit", "nuclei", "sigma"])
        self.assertEqual(self.kinds(), ["metasploit", "nuclei", "sigma"])


if __name__ == "__main__":
    unittest.main()
