"""Tests for digest.py's per-article line. Stdlib only, in-memory SQLite, and
nothing is written to the vault.

    .venv\\Scripts\\python.exe -m unittest -v test_digest
"""
import sqlite3
import unittest

import digest

EM = chr(0x2014)   # em dash
EN = chr(0x2013)   # en dash


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE cve_mentions (article_id INTEGER, cve_id TEXT, cvss_score REAL);"
        "CREATE TABLE vendor_matches (article_id INTEGER, vendor_term TEXT);"
        "CREATE TABLE entity_matches (article_id INTEGER, entity_name TEXT);"
    )
    return conn


def _line(title):
    return digest._format_line(_conn(), {"id": 1, "title": title, "link": "https://example.test/a"})


class TitleFormatting(unittest.TestCase):
    def test_an_em_dash_becomes_a_spaced_hyphen(self):
        # The real title from the 28 September 2026 digest.
        line = _line(f"Introducing ADE-Skills {EM} Adversarial Detection Engineering Knowledge Base")
        self.assertEqual(line, "- [Introducing ADE-Skills - Adversarial Detection Engineering Knowledge Base]"
                               "(https://example.test/a)")
        self.assertNotIn(EM, _line(f"tight{EM}no spaces{EM}twice"))
        self.assertIn("tight - no spaces - twice", _line(f"tight{EM}no spaces{EM}twice"))

    def test_other_dashes_and_digits_are_left_alone(self):
        self.assertIn(f"pages 3{EN}5 - fine, since 2014", _line(f"pages 3{EN}5 - fine, since 2014"))

    def test_whitespace_is_still_collapsed(self):
        self.assertIn("[Advisory: path deletion in a task]", _line("Advisory:\n      path deletion\n\n  in a task"))


if __name__ == "__main__":
    unittest.main()
