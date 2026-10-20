# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SQLite schema and access for NekoCTI's archive.

The source side is generic (a `sources` table, no source-specific columns),
so new feeds slot in without a rewrite. Dedup is layered: normalized link,
the feed's guid, and a content hash, since the link alone misses duplicates.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

DB_PATH = Path(__file__).resolve().parent / "nekocti.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    feed_url TEXT NOT NULL,
    etag TEXT,
    modified TEXT,
    last_polled_at TEXT
);

CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    guid TEXT,
    link TEXT NOT NULL,
    normalized_link TEXT NOT NULL,
    title TEXT NOT NULL,
    published_at TEXT,
    fetched_at TEXT NOT NULL,
    description TEXT,
    full_text TEXT,
    content_hash TEXT NOT NULL,
    high_ticket INTEGER NOT NULL DEFAULT 0,
    is_breach INTEGER NOT NULL DEFAULT 0,
    UNIQUE(normalized_link, guid, content_hash)
);

CREATE TABLE IF NOT EXISTS cve_mentions (
    id INTEGER PRIMARY KEY,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    cve_id TEXT NOT NULL,
    cvss_score REAL
);

CREATE TABLE IF NOT EXISTS vendor_matches (
    id INTEGER PRIMARY KEY,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    category TEXT NOT NULL,
    vendor_term TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entity_matches (
    id INTEGER PRIMARY KEY,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    entity_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaign_matches (
    id INTEGER PRIMARY KEY,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    campaign_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS article_images (
    id INTEGER PRIMARY KEY,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    image_url TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS attack_techniques (
    id INTEGER PRIMARY KEY,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    confidence TEXT
);

-- Public PoC repos per captured CVE (pocs.py). poc_checks records when each
-- CVE was checked, so "checked, none found" differs from "not checked yet".
CREATE TABLE IF NOT EXISTS cve_pocs (
    id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL,
    repo_full_name TEXT NOT NULL,
    repo_url TEXT NOT NULL,
    description TEXT,
    stars INTEGER NOT NULL DEFAULT 0,
    repo_created_at TEXT,
    repo_pushed_at TEXT
);

CREATE TABLE IF NOT EXISTS poc_checks (
    cve_id TEXT PRIMARY KEY,
    checked_at TEXT NOT NULL
);

-- Per-CVE ATT&CK tags in two confidence tiers (cve_attack.py): "expert" from
-- MITRE CTID's KEV mapping, "llm" from local classification. Never blended.
-- cve_attack_checks marks a CVE done by either tier; no recheck window.
CREATE TABLE IF NOT EXISTS cve_attack_techniques (
    id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    confidence TEXT NOT NULL,
    mapping_type TEXT,
    evidence TEXT,
    source_url TEXT
);

CREATE TABLE IF NOT EXISTS cve_attack_checks (
    cve_id TEXT PRIMARY KEY,
    checked_at TEXT NOT NULL
);

-- Per-CVE enrichment (enrich.py): NVD severity, EPSS prediction and CISA KEV
-- membership. Kept apart from cve_mentions.cvss_score, which is whatever an
-- article claimed, so the dashboard can say where a score came from. Each
-- source has its own checked_at because they refresh at different rates.
CREATE TABLE IF NOT EXISTS cve_scores (
    cve_id TEXT PRIMARY KEY,
    nvd_base_score REAL,
    nvd_severity TEXT,
    nvd_cvss_version TEXT,
    nvd_vector TEXT,
    nvd_cwes TEXT,
    nvd_published TEXT,
    nvd_last_modified TEXT,
    nvd_status TEXT,
    nvd_checked_at TEXT,
    epss_score REAL,
    epss_percentile REAL,
    epss_date TEXT,
    epss_checked_at TEXT,
    kev_listed INTEGER NOT NULL DEFAULT 0,
    kev_date_added TEXT,
    kev_ransomware TEXT,
    kev_checked_at TEXT
);

-- Every vendor and product the CVE record lists as affected (cverecord.py),
-- replaced on each fetch. The CVE-to-vendor link, instead of whatever
-- vendors an article happened to name.
CREATE TABLE IF NOT EXISTS cve_affected (
    cve_id TEXT NOT NULL,
    vendor TEXT,
    product TEXT
);
CREATE INDEX IF NOT EXISTS cve_affected_cve ON cve_affected(cve_id);

-- Nuclei templates, Metasploit exploit modules and Sigma rules per captured
-- CVE (coverage.py), as links. Each kind is replaced whole when its listing
-- is re-read; coverage_refreshes says when, even if nothing matched.
CREATE TABLE IF NOT EXISTS cve_coverage (
    cve_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    ref TEXT NOT NULL,
    link TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS cve_coverage_cve ON cve_coverage(cve_id);

-- Each CVE's priority (priority.py): score, band and the evidence behind it
-- as a JSON list, replaced whole on every check.
CREATE TABLE IF NOT EXISTS cve_priority (
    cve_id TEXT PRIMARY KEY,
    score INTEGER NOT NULL,
    band TEXT NOT NULL,
    why TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS coverage_refreshes (
    kind TEXT PRIMARY KEY,
    refreshed_at TEXT NOT NULL
);

-- Which CVE a piece of coverage claims is exploited, and from which article.
CREATE TABLE IF NOT EXISTS cve_exploit_reports (
    cve_id TEXT NOT NULL,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    detected_at TEXT NOT NULL,
    PRIMARY KEY (cve_id, article_id)
);

-- Dashboard login sessions (auth.py). Only a hash of each token is stored.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);

-- Full-text search. External content: the text stays in articles, and the
-- triggers keep the index in sync.
CREATE VIRTUAL TABLE IF NOT EXISTS articles_fts USING fts5(
    title, full_text, description, content='articles', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS articles_ai AFTER INSERT ON articles BEGIN
    INSERT INTO articles_fts(rowid, title, full_text, description)
    VALUES (new.id, new.title, new.full_text, new.description);
END;

CREATE TRIGGER IF NOT EXISTS articles_ad AFTER DELETE ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, full_text, description)
    VALUES ('delete', old.id, old.title, old.full_text, old.description);
END;

CREATE TRIGGER IF NOT EXISTS articles_au AFTER UPDATE ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, full_text, description)
    VALUES ('delete', old.id, old.title, old.full_text, old.description);
    INSERT INTO articles_fts(rowid, title, full_text, description)
    VALUES (new.id, new.title, new.full_text, new.description);
END;
"""

# Columns added after real installs existed: ALTER TABLE ADD COLUMN, no
# migration framework for a single-file personal database.
_MIGRATIONS = [
    ("articles", "is_breach", "INTEGER NOT NULL DEFAULT 0"),
    ("articles", "attack_classified_at", "TEXT"),
    ("articles", "mentions_poc", "INTEGER NOT NULL DEFAULT 0"),
    ("articles", "exploited_in_wild", "INTEGER NOT NULL DEFAULT 0"),
    # The CVE record (cverecord.py): the CNA's or CISA's score, kept apart
    # from NVD's so the dashboard can say which one it shows.
    ("cve_scores", "rec_base_score", "REAL"),
    ("cve_scores", "rec_severity", "TEXT"),
    ("cve_scores", "rec_cvss_version", "TEXT"),
    ("cve_scores", "rec_vector", "TEXT"),
    ("cve_scores", "rec_score_source", "TEXT"),
    ("cve_scores", "rec_cwes", "TEXT"),
    ("cve_scores", "rec_state", "TEXT"),
    ("cve_scores", "rec_published", "TEXT"),
    ("cve_scores", "rec_checked_at", "TEXT"),
    ("cve_scores", "ssvc_exploitation", "TEXT"),
    ("cve_scores", "ssvc_automatable", "TEXT"),
    ("cve_scores", "ssvc_technical_impact", "TEXT"),
    # The PoC-in-GitHub file's git blob hash when last read (pocs.py), "" for
    # "no file"; an unchanged hash means nothing to fetch.
    ("poc_checks", "blob_sha", "TEXT"),
    # The priority score (priority.py), recomputed every check. high_ticket
    # is derived from the band.
    ("articles", "priority_score", "INTEGER NOT NULL DEFAULT 0"),
    ("articles", "priority_band", "TEXT"),
    ("articles", "priority_why", "TEXT"),
]


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        for table, column, coltype in _MIGRATIONS:
            existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
        # A fresh FTS table needs a one-time backfill. COUNT(*) on an
        # external-content table passes through to `articles`, so it always
        # looks full; the shadow index table is the real signal.
        idx_count = conn.execute("SELECT COUNT(*) c FROM articles_fts_idx").fetchone()["c"]
        real_count = conn.execute("SELECT COUNT(*) c FROM articles").fetchone()["c"]
        if idx_count == 0 and real_count > 0:
            conn.execute("INSERT INTO articles_fts(articles_fts) VALUES('rebuild')")
        conn.commit()
    finally:
        conn.close()


def normalize_link(url: str) -> str:
    """Drop www., trailing slashes, query and fragment, so the same article
    isn't stored twice."""
    parts = urlsplit(url)
    netloc = parts.netloc.lower().removeprefix("www.")
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme, netloc, path, "", ""))


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def upsert_source(conn: sqlite3.Connection, name: str, feed_url: str) -> int:
    conn.execute(
        "INSERT INTO sources (name, feed_url) VALUES (?, ?) "
        "ON CONFLICT(name) DO UPDATE SET feed_url = excluded.feed_url",
        (name, feed_url),
    )
    conn.commit()
    row = conn.execute("SELECT id FROM sources WHERE name = ?", (name,)).fetchone()
    return row["id"]


def update_source_polled(conn: sqlite3.Connection, source_id: int,
                          etag: str | None, modified: str | None, polled_at: str) -> None:
    conn.execute(
        "UPDATE sources SET etag = ?, modified = ?, last_polled_at = ? WHERE id = ?",
        (etag, modified, polled_at, source_id),
    )
    conn.commit()


def article_exists(conn: sqlite3.Connection, normalized_link: str, guid: str | None) -> bool:
    """Link and guid only: the content hash needs the full-article fetch this
    check exists to avoid."""
    row = conn.execute(
        "SELECT 1 FROM articles WHERE normalized_link = ? AND "
        "(guid = ? OR guid IS NULL) LIMIT 1",
        (normalized_link, guid),
    ).fetchone()
    return row is not None


def insert_article(conn: sqlite3.Connection, *, source_id: int, guid: str | None,
                    link: str, title: str, published_at: str | None,
                    fetched_at: str, description: str, full_text: str | None,
                    high_ticket: bool, is_breach: bool = False,
                    mentions_poc: bool = False, exploited_in_wild: bool = False) -> int | None:
    """The new row id, or None if the record already existed."""
    chash = content_hash(full_text or description)
    nlink = normalize_link(link)
    cur = conn.execute(
        "INSERT OR IGNORE INTO articles (source_id, guid, link, normalized_link, title, "
        "published_at, fetched_at, description, full_text, content_hash, high_ticket, is_breach, "
        "mentions_poc, exploited_in_wild) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (source_id, guid, link, nlink, title, published_at, fetched_at,
         description, full_text, chash, int(high_ticket), int(is_breach), int(mentions_poc),
         int(exploited_in_wild)),
    )
    conn.commit()
    return cur.lastrowid if cur.rowcount else None


def backfill_exploited_in_wild(conn: sqlite3.Connection, evidence_fn) -> dict:
    """Rescan stored articles for reported exploitation, writing the per-CVE
    claims and the article flag. Each article's old claims are cleared first,
    so a tuned pattern can remove a false positive as well as add one."""
    rows = conn.execute(
        "SELECT id, title, description, full_text, exploited_in_wild FROM articles"
    ).fetchall()
    now = datetime.now(timezone.utc).isoformat()
    stats = {"articles_changed": 0, "cve_reports": 0, "cves": set()}
    for row in rows:
        body = row["full_text"] or row["description"] or ""
        title_claim, cve_ids = evidence_fn(row["title"], body)
        flag = int(bool(title_claim or cve_ids))
        conn.execute("DELETE FROM cve_exploit_reports WHERE article_id = ?", (row["id"],))
        if cve_ids:
            conn.executemany(
                "INSERT OR REPLACE INTO cve_exploit_reports (cve_id, article_id, detected_at) "
                "VALUES (?, ?, ?)",
                [(c, row["id"], now) for c in sorted(cve_ids)],
            )
            stats["cve_reports"] += len(cve_ids)
            stats["cves"].update(cve_ids)
        if flag != row["exploited_in_wild"]:
            conn.execute("UPDATE articles SET exploited_in_wild = ? WHERE id = ?", (flag, row["id"]))
            stats["articles_changed"] += 1
    conn.commit()
    stats["distinct_cves"] = len(stats.pop("cves"))
    return stats


# Sources whose ingesters attach exactly one CVE per article (kev.py, ghsa.py)
# and never run the text extractor, so a text re-scan leaves them alone.
# Names must match their db.upsert_source() calls.
STRUCTURED_SOURCES = ("CISA KEV", "GitHub Security Advisories")


def backfill_cve_mentions(conn: sqlite3.Connection, extract_fn) -> dict:
    """Re-scan stored articles with the current CVE extractor and add any new
    mention. Only ever adds: existing mentions and scores are kept.
    high_ticket is left to the priority score (priority.py)."""
    existing: dict[int, set[str]] = {}
    for row in conn.execute("SELECT article_id, cve_id FROM cve_mentions"):
        existing.setdefault(row["article_id"], set()).add(row["cve_id"])
    rows = conn.execute(
        "SELECT a.id, a.description, a.full_text FROM articles a "
        "JOIN sources s ON s.id = a.source_id "
        f"WHERE s.name NOT IN ({', '.join('?' for _ in STRUCTURED_SOURCES)})",
        STRUCTURED_SOURCES,
    ).fetchall()
    stats = {"mentions_added": 0, "articles_changed": 0, "cves": set()}
    for row in rows:
        found = extract_fn(row["full_text"] or row["description"] or "")
        new = [(cve_id, score) for cve_id, score in found
               if cve_id not in existing.get(row["id"], set())]
        if not new:
            continue
        conn.executemany(
            "INSERT INTO cve_mentions (article_id, cve_id, cvss_score) VALUES (?, ?, ?)",
            [(row["id"], cve_id, score) for cve_id, score in new],
        )
        stats["mentions_added"] += len(new)
        stats["articles_changed"] += 1
        stats["cves"].update(cve_id for cve_id, _ in new)
    conn.commit()
    stats["distinct_cves"] = len(stats.pop("cves"))
    return stats


def get_exploit_reports(conn: sqlite3.Connection, cve_ids: list[str]) -> dict[str, int]:
    """How many captured articles report each of these CVEs as exploited."""
    if not cve_ids:
        return {}
    marks = ", ".join("?" for _ in cve_ids)
    rows = conn.execute(
        f"SELECT cve_id, COUNT(*) n FROM cve_exploit_reports WHERE cve_id IN ({marks}) "
        "GROUP BY cve_id", cve_ids
    ).fetchall()
    return {r["cve_id"]: r["n"] for r in rows}


def insert_cve_mentions(conn: sqlite3.Connection, article_id: int,
                         mentions: list[tuple[str, float | None]]) -> None:
    conn.executemany(
        "INSERT INTO cve_mentions (article_id, cve_id, cvss_score) VALUES (?, ?, ?)",
        [(article_id, cve_id, score) for cve_id, score in mentions],
    )
    conn.commit()


def insert_vendor_matches(conn: sqlite3.Connection, article_id: int,
                           matches: list[tuple[str, str]]) -> None:
    conn.executemany(
        "INSERT INTO vendor_matches (article_id, category, vendor_term) VALUES (?, ?, ?)",
        [(article_id, category, term) for category, term in matches],
    )
    conn.commit()


def insert_entity_matches(conn: sqlite3.Connection, article_id: int,
                           entities: list[str]) -> None:
    conn.executemany(
        "INSERT INTO entity_matches (article_id, entity_name) VALUES (?, ?)",
        [(article_id, name) for name in entities],
    )
    conn.commit()


def insert_campaign_matches(conn: sqlite3.Connection, article_id: int,
                             campaigns: list[str]) -> None:
    conn.executemany(
        "INSERT INTO campaign_matches (article_id, campaign_name) VALUES (?, ?)",
        [(article_id, name) for name in campaigns],
    )
    conn.commit()


def insert_article_images(conn: sqlite3.Connection, article_id: int,
                           image_urls: list[str]) -> None:
    conn.executemany(
        "INSERT INTO article_images (article_id, image_url, position) VALUES (?, ?, ?)",
        [(article_id, url, i) for i, url in enumerate(image_urls)],
    )
    conn.commit()


def articles_needing_attack_classification(conn: sqlite3.Connection, limit: int) -> list[sqlite3.Row]:
    """Unclassified articles that have some text to classify."""
    return conn.execute(
        "SELECT id, title, full_text, description FROM articles "
        "WHERE attack_classified_at IS NULL "
        "AND (full_text IS NOT NULL OR description IS NOT NULL) "
        "ORDER BY fetched_at DESC LIMIT ?",
        (limit,),
    ).fetchall()


def insert_attack_techniques(conn: sqlite3.Connection, article_id: int,
                              techniques: list[tuple[str, str, str]]) -> None:
    conn.executemany(
        "INSERT INTO attack_techniques (article_id, technique_id, technique_name, confidence) "
        "VALUES (?, ?, ?, ?)",
        [(article_id, tid, name, conf) for tid, name, conf in techniques],
    )
    conn.execute(
        "UPDATE articles SET attack_classified_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), article_id),
    )
    conn.commit()


def search_articles(conn: sqlite3.Connection, query: str, limit: int = 100) -> list[sqlite3.Row]:
    """FTS5 search ranked by relevance. Malformed FTS syntax (a stray quote or
    operator) is retried as one literal phrase."""
    sql = (
        "SELECT a.* FROM articles a JOIN articles_fts f ON f.rowid = a.id "
        "WHERE articles_fts MATCH ? ORDER BY rank LIMIT ?"
    )
    try:
        return conn.execute(sql, (query, limit)).fetchall()
    except sqlite3.OperationalError:
        phrase = '"' + query.replace('"', '""') + '"'
        return conn.execute(sql, (phrase, limit)).fetchall()


def get_poc_blob_shas(conn: sqlite3.Connection) -> dict[str, str | None]:
    """The PoC file hash each checked CVE was last read at."""
    return {r["cve_id"]: r["blob_sha"] for r in conn.execute("SELECT cve_id, blob_sha FROM poc_checks")}


def replace_cve_pocs(conn: sqlite3.Connection, cve_id: str, pocs: list[dict],
                     blob_sha: str | None = None) -> None:
    """Replace this CVE's PoC repos with the current set (stars change, repos
    vanish) and mark it checked, whether or not any were found."""
    conn.execute("DELETE FROM cve_pocs WHERE cve_id = ?", (cve_id,))
    conn.executemany(
        "INSERT INTO cve_pocs (cve_id, repo_full_name, repo_url, description, stars, "
        "repo_created_at, repo_pushed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (cve_id, p.get("full_name", ""), p.get("html_url", ""), p.get("description"),
             p.get("stargazers_count", 0) or 0, p.get("created_at"), p.get("pushed_at"))
            for p in pocs
        ],
    )
    conn.execute(
        "INSERT INTO poc_checks (cve_id, checked_at, blob_sha) VALUES (?, ?, ?) "
        "ON CONFLICT(cve_id) DO UPDATE SET checked_at = excluded.checked_at, blob_sha = excluded.blob_sha",
        (cve_id, datetime.now(timezone.utc).isoformat(), blob_sha),
    )
    conn.commit()


def all_cve_ids(conn: sqlite3.Connection) -> list[str]:
    """Every captured CVE, newest identifier first."""
    rows = conn.execute(
        "SELECT DISTINCT cve_id FROM cve_mentions ORDER BY cve_id DESC"
    ).fetchall()
    return [r["cve_id"] for r in rows]


def cves_needing_nvd(conn: sqlite3.Connection, recheck_after_days: int, limit: int) -> list[str]:
    """CVEs to ask NVD about next, in triage order because NVD is rate-limited
    and a run is bounded by `limit`: never-checked first, then high ticket,
    watchlist matches, no severity at all, newest. Re-checks only matter for
    entries NVD hasn't finished analysing."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=recheck_after_days)).isoformat()
    rows = conn.execute(
        """
        SELECT cm.cve_id,
               MAX(a.high_ticket) AS ht,
               MAX(CASE WHEN vm.article_id IS NOT NULL THEN 1 ELSE 0 END) AS watched,
               MAX(CASE WHEN cm.cvss_score IS NULL THEN 1 ELSE 0 END) AS no_score,
               MAX(CASE WHEN cs.nvd_checked_at IS NULL THEN 1 ELSE 0 END) AS never
        FROM cve_mentions cm
        JOIN articles a ON a.id = cm.article_id
        LEFT JOIN vendor_matches vm ON vm.article_id = cm.article_id
        LEFT JOIN cve_scores cs ON cs.cve_id = cm.cve_id
        WHERE cs.nvd_checked_at IS NULL
           OR (cs.nvd_status IS NOT NULL AND cs.nvd_status != 'Analyzed' AND cs.nvd_checked_at < ?)
        GROUP BY cm.cve_id
        ORDER BY never DESC, ht DESC, watched DESC, no_score DESC, cm.cve_id DESC
        LIMIT ?
        """,
        (cutoff, limit),
    ).fetchall()
    return [r["cve_id"] for r in rows]


def cves_needing_epss(conn: sqlite3.Connection, recheck_after_hours: int) -> list[str]:
    """EPSS is recomputed daily and batched, so every captured CVE is due."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=recheck_after_hours)).isoformat()
    rows = conn.execute(
        "SELECT DISTINCT cm.cve_id FROM cve_mentions cm "
        "LEFT JOIN cve_scores cs ON cs.cve_id = cm.cve_id "
        "WHERE cs.epss_checked_at IS NULL OR cs.epss_checked_at < ? "
        "ORDER BY cm.cve_id DESC",
        (cutoff,),
    ).fetchall()
    return [r["cve_id"] for r in rows]


def _upsert_cve_score(conn: sqlite3.Connection, cve_id: str, values: dict) -> None:
    cols = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    updates = ", ".join(f"{c} = excluded.{c}" for c in values)
    conn.execute(
        f"INSERT INTO cve_scores (cve_id, {cols}) VALUES (?, {placeholders}) "
        f"ON CONFLICT(cve_id) DO UPDATE SET {updates}",
        (cve_id, *values.values()),
    )


def record_nvd_score(conn: sqlite3.Connection, cve_id: str, data: dict | None) -> None:
    """What NVD says about one CVE. `data` is None when NVD has no record,
    which is still an answer: the check time is written so it isn't retried
    every run."""
    values = {"nvd_checked_at": datetime.now(timezone.utc).isoformat()}
    if data:
        values.update({
            "nvd_base_score": data.get("base_score"),
            "nvd_severity": data.get("severity"),
            "nvd_cvss_version": data.get("version"),
            "nvd_vector": data.get("vector"),
            "nvd_cwes": ", ".join(data.get("cwes", [])) or None,
            "nvd_published": data.get("published"),
            "nvd_last_modified": data.get("last_modified"),
            "nvd_status": data.get("status"),
        })
    _upsert_cve_score(conn, cve_id, values)
    conn.commit()


def record_epss_scores(conn: sqlite3.Connection, scores: dict[str, dict]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for cve_id, s in scores.items():
        _upsert_cve_score(conn, cve_id, {
            "epss_score": s.get("epss"),
            "epss_percentile": s.get("percentile"),
            "epss_date": s.get("date"),
            "epss_checked_at": now,
        })
    conn.commit()


def record_kev_membership(conn: sqlite3.Connection, kev: dict[str, dict]) -> int:
    """Set the KEV flag on every captured CVE in the catalog and clear it on
    any that isn't, so a stale flag can't survive a catalog change."""
    now = datetime.now(timezone.utc).isoformat()
    marked = 0
    for cve_id in all_cve_ids(conn):
        entry = kev.get(cve_id)
        _upsert_cve_score(conn, cve_id, {
            "kev_listed": 1 if entry else 0,
            "kev_date_added": (entry or {}).get("dateAdded"),
            "kev_ransomware": (entry or {}).get("knownRansomwareCampaignUse"),
            "kev_checked_at": now,
        })
        marked += 1 if entry else 0
    conn.commit()
    return marked


def cves_needing_record(conn: sqlite3.Connection, recheck_after_days: int,
                        young_days: int, limit: int) -> list[str]:
    """CVEs to read the CVE record for next: never read first, newest
    identifier first. A record is read again only while it's young and still
    missing a score or SSVC, because CNAs and CISA add those days after
    publication; a rejected record is final."""
    now = datetime.now(timezone.utc)
    recheck = (now - timedelta(days=recheck_after_days)).isoformat()
    young = (now - timedelta(days=young_days)).isoformat()
    rows = conn.execute(
        """
        SELECT DISTINCT cm.cve_id, cs.rec_checked_at IS NULL AS never
        FROM cve_mentions cm
        LEFT JOIN cve_scores cs ON cs.cve_id = cm.cve_id
        WHERE cs.rec_checked_at IS NULL
           OR (cs.rec_checked_at < ?
               AND COALESCE(cs.rec_state, '') != 'REJECTED'
               AND (cs.rec_base_score IS NULL OR cs.ssvc_exploitation IS NULL)
               AND COALESCE(cs.rec_published, cs.nvd_published, ?) >= ?)
        ORDER BY never DESC, cm.cve_id DESC
        LIMIT ?
        """,
        (recheck, now.isoformat(), young, limit),
    ).fetchall()
    return [r["cve_id"] for r in rows]


def record_cve_record(conn: sqlite3.Connection, cve_id: str, data: dict | None) -> None:
    """What the CVE record says about one CVE. `data` is None when there is no
    record yet (a reserved ID), which is still an answer: the check time is
    written, so it's retried on the recheck schedule rather than every run."""
    values = {"rec_checked_at": datetime.now(timezone.utc).isoformat()}
    if data is None:
        values["rec_state"] = "MISSING"
    else:
        values.update({
            "rec_base_score": data.get("base_score"),
            "rec_severity": data.get("severity"),
            "rec_cvss_version": data.get("version"),
            "rec_vector": data.get("vector"),
            "rec_score_source": data.get("score_source"),
            "rec_cwes": ", ".join(data.get("cwes", [])) or None,
            "rec_state": data.get("state"),
            "rec_published": data.get("published"),
            "ssvc_exploitation": data.get("ssvc_exploitation"),
            "ssvc_automatable": data.get("ssvc_automatable"),
            "ssvc_technical_impact": data.get("ssvc_technical_impact"),
        })
        conn.execute("DELETE FROM cve_affected WHERE cve_id = ?", (cve_id,))
        conn.executemany(
            "INSERT INTO cve_affected (cve_id, vendor, product) VALUES (?, ?, ?)",
            [(cve_id, v, p) for v, p in data.get("affected", [])],
        )
    _upsert_cve_score(conn, cve_id, values)
    conn.commit()


def get_cve_affected(conn: sqlite3.Connection, cve_ids: list[str]) -> dict[str, list[tuple[str, str]]]:
    """(vendor, product) pairs per CVE, for the CVEs that have a record."""
    if not cve_ids:
        return {}
    marks = ", ".join("?" for _ in cve_ids)
    out: dict[str, list[tuple[str, str]]] = {}
    for r in conn.execute(
        f"SELECT cve_id, vendor, product FROM cve_affected WHERE cve_id IN ({marks})", cve_ids
    ):
        out.setdefault(r["cve_id"], []).append((r["vendor"] or "", r["product"] or ""))
    return out


def get_small_article_titles(conn: sqlite3.Connection, cve_ids: list[str],
                             max_cves: int = 5) -> dict[str, list[str]]:
    """Titles of the articles naming each CVE, from articles naming at most
    `max_cves` CVEs: the fallback for a CVE whose record lists no affected
    product. Titles, not bodies, because a weekly report names few CVEs but
    many vendors; its title names its subject."""
    if not cve_ids:
        return {}
    marks = ", ".join("?" for _ in cve_ids)
    rows = conn.execute(
        f"""
        SELECT cm.cve_id, a.title FROM cve_mentions cm
        JOIN articles a ON a.id = cm.article_id
        WHERE cm.cve_id IN ({marks})
          AND (SELECT COUNT(DISTINCT cm2.cve_id) FROM cve_mentions cm2
               WHERE cm2.article_id = cm.article_id) <= ?
        """,
        (*cve_ids, max_cves),
    ).fetchall()
    out: dict[str, list[str]] = {}
    for r in rows:
        out.setdefault(r["cve_id"], []).append(r["title"] or "")
    return out


def replace_coverage(conn: sqlite3.Connection, kind: str, rows: list[tuple[str, str, str]]) -> None:
    """Every (cve_id, ref, link) of one kind, replacing the previous set."""
    conn.execute("DELETE FROM cve_coverage WHERE kind = ?", (kind,))
    conn.executemany("INSERT INTO cve_coverage (cve_id, kind, ref, link) VALUES (?, ?, ?, ?)",
                     [(cve, kind, ref, link) for cve, ref, link in rows])
    conn.execute(
        "INSERT INTO coverage_refreshes (kind, refreshed_at) VALUES (?, ?) "
        "ON CONFLICT(kind) DO UPDATE SET refreshed_at = excluded.refreshed_at",
        (kind, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def get_coverage_refreshed_at(conn: sqlite3.Connection) -> dict[str, str]:
    return {r["kind"]: r["refreshed_at"] for r in conn.execute("SELECT kind, refreshed_at FROM coverage_refreshes")}


def get_cve_coverage(conn: sqlite3.Connection, cve_ids: list[str]) -> dict[str, list[dict]]:
    """[{kind, ref, link}] per CVE."""
    if not cve_ids:
        return {}
    marks = ", ".join("?" for _ in cve_ids)
    out: dict[str, list[dict]] = {}
    for r in conn.execute(
        f"SELECT cve_id, kind, ref, link FROM cve_coverage WHERE cve_id IN ({marks}) ORDER BY kind, ref", cve_ids
    ):
        out.setdefault(r["cve_id"], []).append({"kind": r["kind"], "ref": r["ref"], "link": r["link"]})
    return out


def get_poc_flags(conn: sqlite3.Connection, cve_ids: list[str]) -> dict[str, tuple[bool, bool]]:
    """(has a public PoC repo, coverage describes a PoC) per CVE, the second
    only from articles naming 5 or fewer CVEs."""
    if not cve_ids:
        return {}
    marks = ", ".join("?" for _ in cve_ids)
    repos = {r[0] for r in conn.execute(f"SELECT DISTINCT cve_id FROM cve_pocs WHERE cve_id IN ({marks})", cve_ids)}
    mentioned = {r[0] for r in conn.execute(
        f"SELECT DISTINCT cm.cve_id FROM cve_mentions cm JOIN articles a ON a.id = cm.article_id "
        f"WHERE cm.cve_id IN ({marks}) AND a.mentions_poc = 1 "
        f"AND (SELECT COUNT(DISTINCT cm2.cve_id) FROM cve_mentions cm2 WHERE cm2.article_id = a.id) <= 5",
        cve_ids)}
    return {c: (c in repos, c in mentioned) for c in cve_ids}


def get_freshness(conn: sqlite3.Connection) -> dict:
    """How current the facts are: when each lookup last ran and how much is
    still waiting. The archive is never pruned, so freshness means re-checked
    facts, not fewer rows."""
    one = lambda sql: conn.execute(sql).fetchone()[0]
    return {
        "last_article_fetched_at": one("SELECT MAX(fetched_at) FROM articles"),
        "last_epss_at": one("SELECT MAX(epss_checked_at) FROM cve_scores"),
        "epss_data_date": one("SELECT MAX(epss_date) FROM cve_scores"),
        "last_kev_at": one("SELECT MAX(kev_checked_at) FROM cve_scores"),
        "last_nvd_at": one("SELECT MAX(nvd_checked_at) FROM cve_scores"),
        "cves_total": one("SELECT COUNT(DISTINCT cve_id) FROM cve_mentions"),
        # A severity from NVD or the CVE record counts; rejected CVEs never get one.
        "cves_awaiting_severity": one(
            "SELECT COUNT(DISTINCT cm.cve_id) FROM cve_mentions cm "
            "LEFT JOIN cve_scores cs ON cs.cve_id = cm.cve_id "
            "WHERE cs.nvd_base_score IS NULL AND cs.rec_base_score IS NULL "
            "AND COALESCE(cs.rec_state, '') != 'REJECTED'"),
        "cves_with_severity": one(
            "SELECT COUNT(*) FROM cve_scores WHERE nvd_base_score IS NOT NULL OR rec_base_score IS NOT NULL"),
        "kev_listed": one("SELECT COUNT(*) FROM cve_scores WHERE kev_listed = 1"),
        "reported_exploited": one("SELECT COUNT(DISTINCT cve_id) FROM cve_exploit_reports"),
    }


def get_cve_scores(conn: sqlite3.Connection, cve_ids: list[str]) -> dict[str, sqlite3.Row]:
    if not cve_ids:
        return {}
    marks = ", ".join("?" for _ in cve_ids)
    rows = conn.execute(
        f"SELECT * FROM cve_scores WHERE cve_id IN ({marks})", cve_ids
    ).fetchall()
    return {r["cve_id"]: r for r in rows}


def replace_cve_priority(conn: sqlite3.Connection, rows: list[tuple[str, int, str, str]]) -> None:
    """Every (cve_id, score, band, why JSON), replacing the previous set."""
    conn.execute("DELETE FROM cve_priority")
    conn.executemany("INSERT INTO cve_priority (cve_id, score, band, why) VALUES (?, ?, ?, ?)", rows)
    conn.commit()


def set_article_priorities(conn: sqlite3.Connection, rows: list[tuple[int, str, str, int, int]]) -> None:
    """(score, band, why JSON, high_ticket, article id) for each article."""
    conn.executemany(
        "UPDATE articles SET priority_score = ?, priority_band = ?, priority_why = ?, high_ticket = ? WHERE id = ?",
        rows,
    )
    conn.commit()


def get_cve_priority(conn: sqlite3.Connection, cve_ids: list[str]) -> dict[str, sqlite3.Row]:
    if not cve_ids:
        return {}
    marks = ", ".join("?" for _ in cve_ids)
    return {r["cve_id"]: r for r in conn.execute(f"SELECT * FROM cve_priority WHERE cve_id IN ({marks})", cve_ids)}


def get_pocs_summary(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """One row per CVE with a public PoC, most-starred first."""
    return conn.execute(
        "SELECT cve_id, COUNT(*) poc_count, MAX(stars) max_stars, "
        "MAX(repo_pushed_at) latest_pushed_at "
        "FROM cve_pocs GROUP BY cve_id ORDER BY max_stars DESC, poc_count DESC"
    ).fetchall()


def get_pocs_for_cve(conn: sqlite3.Connection, cve_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM cve_pocs WHERE cve_id = ? ORDER BY stars DESC", (cve_id,)
    ).fetchall()


def get_all_captured_cve_ids(conn: sqlite3.Connection) -> set[str]:
    return {r["cve_id"] for r in conn.execute("SELECT DISTINCT cve_id FROM cve_mentions").fetchall()}


def get_checked_attack_cve_ids(conn: sqlite3.Connection) -> set[str]:
    return {r["cve_id"] for r in conn.execute("SELECT cve_id FROM cve_attack_checks").fetchall()}


def get_poc_mention_cve_ids(conn: sqlite3.Connection) -> set[str]:
    """The POCS tab's mention-only CVEs: PoC-mentioning articles naming 5 or
    fewer CVEs (a roundup can't be tied to any one of its hundreds)."""
    rows = conn.execute(
        "SELECT DISTINCT cm.cve_id FROM cve_mentions cm JOIN articles a ON a.id = cm.article_id "
        "WHERE a.mentions_poc = 1 "
        "AND (SELECT COUNT(DISTINCT cm2.cve_id) FROM cve_mentions cm2 "
        "     WHERE cm2.article_id = a.id) <= 5"
    ).fetchall()
    return {r["cve_id"] for r in rows}


def get_cve_title(conn: sqlite3.Connection, cve_id: str) -> str | None:
    """A description for a CVE: a GHSA advisory's title if there is one, else
    the newest article title that mentions it."""
    row = conn.execute(
        "SELECT a.title FROM cve_mentions cm "
        "JOIN articles a ON a.id = cm.article_id "
        "JOIN sources s ON s.id = a.source_id "
        "WHERE cm.cve_id = ? "
        "ORDER BY (s.name = 'GitHub Security Advisories') DESC, a.published_at DESC LIMIT 1",
        (cve_id,),
    ).fetchone()
    return row["title"] if row else None


def insert_cve_attack_techniques(conn: sqlite3.Connection, cve_id: str,
                                  rows: list[tuple]) -> None:
    """Each row is (technique_id, technique_name, confidence, mapping_type,
    evidence, source_url); the last three are None for the LLM tier."""
    conn.executemany(
        "INSERT INTO cve_attack_techniques "
        "(cve_id, technique_id, technique_name, confidence, mapping_type, evidence, source_url) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(cve_id, *row) for row in rows],
    )
    conn.commit()


def mark_cve_attack_checked(conn: sqlite3.Connection, cve_id: str) -> None:
    conn.execute(
        "INSERT INTO cve_attack_checks (cve_id, checked_at) VALUES (?, ?) "
        "ON CONFLICT(cve_id) DO UPDATE SET checked_at = excluded.checked_at",
        (cve_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def cves_needing_llm_attack_classification(conn: sqlite3.Connection, limit: int) -> list[str]:
    """POCS-tab CVEs not yet covered by either tier. The expert pass runs
    first, so anything left has no expert mapping."""
    eligible = {r["cve_id"] for r in get_pocs_summary(conn)} | get_poc_mention_cve_ids(conn)
    checked = get_checked_attack_cve_ids(conn)
    remaining = sorted(eligible - checked)
    return remaining[:limit]


def get_cve_attack_techniques(conn: sqlite3.Connection, cve_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT technique_id, technique_name, confidence, mapping_type, evidence, source_url "
        "FROM cve_attack_techniques WHERE cve_id = ? "
        "ORDER BY confidence = 'expert' DESC, technique_id",
        (cve_id,),
    ).fetchall()


def get_cve_attack_techniques_bulk(conn: sqlite3.Connection, cve_ids: list[str]) -> dict[str, list[dict]]:
    """Bulk fetch for the POCS overview, one query for every row."""
    if not cve_ids:
        return {}
    placeholders = ",".join("?" for _ in cve_ids)
    rows = conn.execute(
        f"SELECT cve_id, technique_id, technique_name, confidence FROM cve_attack_techniques "
        f"WHERE cve_id IN ({placeholders}) ORDER BY confidence = 'expert' DESC, technique_id",
        list(cve_ids),
    ).fetchall()
    out: dict[str, list[dict]] = {}
    for r in rows:
        out.setdefault(r["cve_id"], []).append(
            {"technique_id": r["technique_id"], "technique_name": r["technique_name"], "confidence": r["confidence"]}
        )
    return out
