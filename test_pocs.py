# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the PoC check (pocs.py): one repository listing decides which
files to read, unchanged files are never re-read, and a failed listing never
turns into a sweep of the whole archive. Nothing touches the real database
or the network.

    .venv\\Scripts\\python.exe -m unittest -v test_pocs
"""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import db
import pocs

REPO = [{"full_name": "someone/poc", "html_url": "https://github.com/someone/poc", "stargazers_count": 3}]


class PocCheck(unittest.TestCase):
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
        db.insert_cve_mentions(self.conn, aid, [("CVE-2026-0001", None), ("CVE-2026-0002", None), ("CVE-2026-0003", None)])
        for name, value in (("REQUEST_DELAY_S", 0),):
            q = mock.patch.object(pocs, name, value)
            q.start()
            self.addCleanup(q.stop)

    def run_check(self, index, files):
        fetched = []
        def fetch(cve_id):
            fetched.append(cve_id)
            return files.get(cve_id)
        with mock.patch.object(pocs, "fetch_poc_index", return_value=index), \
                mock.patch.object(pocs, "fetch_pocs_for_cve", side_effect=fetch):
            summary = pocs.check_pocs(self.conn)
        return summary, sorted(fetched)

    def repos(self, cve_id):
        return [r["repo_full_name"] for r in db.get_pocs_for_cve(self.conn, cve_id)]

    def test_only_listed_files_are_read_and_unchanged_ones_never_again(self):
        index = {"CVE-2026-0001": "aaa", "CVE-9999-0001": "zzz"}   # 0002 and 0003 have no file
        summary, fetched = self.run_check(index, {"CVE-2026-0001": REPO})
        self.assertEqual(fetched, ["CVE-2026-0001"])
        self.assertEqual((self.repos("CVE-2026-0001"), summary["files_read"], summary["seen"]), (["someone/poc"], 1, 3))
        summary, fetched = self.run_check(index, {})
        self.assertEqual((fetched, summary["unchanged"], summary["seen"]), ([], 3, 0))

    def test_a_changed_or_removed_file_is_acted_on(self):
        self.run_check({"CVE-2026-0001": "aaa"}, {"CVE-2026-0001": REPO})
        _, fetched = self.run_check({"CVE-2026-0001": "bbb"}, {"CVE-2026-0001": REPO * 2})
        self.assertEqual(fetched, ["CVE-2026-0001"])
        _, fetched = self.run_check({}, {})                      # the file was deleted upstream
        self.assertEqual((fetched, self.repos("CVE-2026-0001")), ([], []))

    def test_a_failed_file_read_is_retried_next_time(self):
        self.run_check({"CVE-2026-0001": "aaa"}, {"CVE-2026-0001": None})
        _, fetched = self.run_check({"CVE-2026-0001": "aaa"}, {"CVE-2026-0001": REPO})
        self.assertEqual(fetched, ["CVE-2026-0001"])

    def test_without_the_listing_only_never_checked_cves_are_read(self):
        self.run_check({"CVE-2026-0001": "aaa"}, {"CVE-2026-0001": REPO})
        summary, fetched = self.run_check(None, {})
        self.assertTrue(summary["index_failed"])
        self.assertEqual(fetched, [])                             # all three were checked already

    def test_a_truncated_listing_is_not_trusted(self):
        with mock.patch.object(pocs.enrich, "get_json", return_value={"truncated": True, "tree": []}):
            self.assertIsNone(pocs.fetch_poc_index())
        tree = {"truncated": False, "tree": [{"path": "2026/CVE-2026-0001.json", "sha": "aaa"},
                                             {"path": "README.md", "sha": "bbb"}]}
        with mock.patch.object(pocs.enrich, "get_json", return_value=tree):
            self.assertEqual(pocs.fetch_poc_index(), {"CVE-2026-0001": "aaa"})


if __name__ == "__main__":
    unittest.main()
