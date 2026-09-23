"""SQLite schema and access for NekoCTI's local archive.

Schema is deliberately generic on the source side (a `sources` table, not
THN-specific fields) so more feeds slot in later without a rewrite -- see
the vault note's own stated design goal.

Dedup uses a layered key rather than trusting one field alone (a real
finding from the 16 September 2026 research pass): normalized link, the
feed's own guid, and a content hash, since relying on raw link comparison
alone measurably misses real duplicates.
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

-- Real public PoC-exploit availability per real CVE already captured --
-- an enrichment lookup (like NVD/EPSS were scoped to be), not a
-- standalone article source, since there's no "new PoC article" to
-- ingest, only "does a public PoC exist for this CVE" against a
-- CVE-keyed lookup. `poc_checks` tracks which CVEs have been checked and
-- when, separate from `cve_pocs` itself, so "checked, zero found" is a
-- real distinct state from "not checked yet" -- without it, both would
-- look identical (no rows in cve_pocs), and a CVE with genuinely no
-- public PoC would get needlessly re-checked forever.
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

-- Real per-CVE MITRE ATT&CK technique tags, two honest confidence tiers
-- (see cve_attack.py for the real research behind this split): "expert"
-- rows come from MITRE's own Center for Threat-Informed Defense KEV-to-
-- ATT&CK mapping (real cited analysis, but only 36 real overlaps against
-- NekoCTI's captured archive as of 17 September 2026); "llm" rows are
-- NekoCTI's own local classification of a CVE's own narrow description
-- text, run only where no expert mapping exists. Never blended silently -
-- confidence is always stored and always shown. `cve_attack_checks` marks
-- a CVE done once classified by either tier - unlike `poc_checks`, there's
-- no recheck window, since a CVE's own real nature doesn't change over
-- time the way PoC availability can.
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

-- Real full-text search, not a LIKE '%term%' scan -- confirmed FTS5 is
-- compiled into this Python's sqlite3 module before relying on it. The
-- "external content" pattern (content='articles') keeps the real text in
-- `articles` itself as the single source of truth; the three triggers
-- below just keep this index in sync with it, so a search never returns
-- stale text after an edit.
-- Per-CVE enrichment, 22 September 2026. One row per CVE ID, filled by
-- enrich.py from three real lookups, kept apart from cve_mentions.cvss_score
-- (which is whatever an article's own text claimed) so the two never
-- overwrite each other and the dashboard can say where a score came from:
--   NVD   -- the official CVSS base score, severity, vector and CWE
--   EPSS  -- FIRST.org's predicted probability of exploitation, and its
--            percentile against every scored CVE
--   KEV   -- membership of CISA's Known Exploited Vulnerabilities catalog,
--            which is confirmed real-world exploitation, not a prediction
-- The checked_at columns are separate because the three refresh at very
-- different rates: EPSS changes daily, NVD rarely after analysis, KEV only
-- when CISA adds an entry.
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

-- Which CVE a piece of coverage claims is being exploited in the wild, and
-- where that claim came from. Article-level flags were too blunt: a monthly
-- patch roundup mentions ninety CVEs and reports two as exploited.
CREATE TABLE IF NOT EXISTS cve_exploit_reports (
    cve_id TEXT NOT NULL,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    detected_at TEXT NOT NULL,
    PRIMARY KEY (cve_id, article_id)
);

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

# Columns added after the table already existed in real installs -- ALTER
# TABLE ADD COLUMN rather than a full migration framework, since this is a
# single-file personal database, not a multi-tenant system.
_MIGRATIONS = [
    ("articles", "is_breach", "INTEGER NOT NULL DEFAULT 0"),
    ("articles", "attack_classified_at", "TEXT"),
    ("articles", "mentions_poc", "INTEGER NOT NULL DEFAULT 0"),
    ("articles", "exploited_in_wild", "INTEGER NOT NULL DEFAULT 0"),
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
        # The sync triggers only fire on inserts/updates from here forward
        # -- a fresh articles_fts table needs a one-time backfill against
        # whatever real rows already existed before it did.
        #
        # A real bug was found here, 16 September 2026: `SELECT COUNT(*)
        # FROM articles_fts` is NOT a reliable "is the index actually
        # built" check for an external-content table -- that query (no
        # MATCH involved) is served by live pass-through to the real
        # `articles` table via the rowid mapping, not by the FTS5 inverted
        # index, so it reports the full real row count immediately after
        # the table is created, before any indexing has happened at all.
        # That made the old `fts_count < real_count` check false from the
        # very first run, silently skipping the rebuild an index-backed
        # MATCH query actually needs -- confirmed live: `articles_fts`
        # reported all 277 real rows while `articles_fts_idx` (the real
        # inverted index shadow table) had zero, and every MATCH query
        # returned nothing despite the content being genuinely present.
        # Checking the real shadow index table directly is the correct
        # signal instead.
        idx_count = conn.execute("SELECT COUNT(*) c FROM articles_fts_idx").fetchone()["c"]
        real_count = conn.execute("SELECT COUNT(*) c FROM articles").fetchone()["c"]
        if idx_count == 0 and real_count > 0:
            conn.execute("INSERT INTO articles_fts(articles_fts) VALUES('rebuild')")
        conn.commit()
    finally:
        conn.close()


def normalize_link(url: str) -> str:
    """Strip scheme-irrelevant noise so the same article isn't re-stored
    twice just because of a www./trailing-slash/query-string difference."""
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
    """Have we already ingested this article at all.

    Checked on link+guid alone, deliberately not content_hash -- a real
    bug found live, 16 September 2026: the hash can only be computed
    AFTER a full-article fetch (or, as a cheap fallback, from the RSS
    description), so checking against it before that fetch happens is a
    chicken-and-egg problem. A first pass tried hashing the description
    as a pre-check, but the row actually stored a hash of the full
    article text once that fetch succeeded, so the two never matched on
    a second poll -- the article got re-fetched and re-processed every
    single run, and the real insert then hit the UNIQUE constraint and
    crashed instead of being skipped cleanly.
    """
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
    """Returns the new row id, or None if this exact record already existed
    (INSERT OR IGNORE as a defensive backstop behind article_exists's own
    link+guid pre-check -- see that function's docstring)."""
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


def backfill_breach_flags(conn: sqlite3.Connection, breach_check) -> int:
    """Re-scan every already-ingested article against the current breach
    heuristic (breach_check(title, body_text) -> bool), since is_breach was
    added after real articles already existed. Sets the flag both ways
    (not just 0 -> 1) so re-running this after tuning the regex actually
    corrects a previous false positive, not just adds new true positives.
    Returns how many rows changed."""
    rows = conn.execute("SELECT id, title, description, full_text, is_breach FROM articles").fetchall()
    changed = 0
    for row in rows:
        body = row["full_text"] or row["description"] or ""
        result = int(breach_check(row["title"], body))
        if result != row["is_breach"]:
            conn.execute("UPDATE articles SET is_breach = ? WHERE id = ?", (result, row["id"]))
            changed += 1
    conn.commit()
    return changed


def backfill_poc_mentions(conn: sqlite3.Connection, poc_mention_check) -> int:
    """Same shape as backfill_breach_flags, for the same reason: mentions_poc
    was added after real articles already existed, and re-running this
    after tuning the regex should correct a real false positive, not just
    add new true positives."""
    rows = conn.execute("SELECT id, title, description, full_text, mentions_poc FROM articles").fetchall()
    changed = 0
    for row in rows:
        body = row["full_text"] or row["description"] or ""
        result = int(poc_mention_check(row["title"], body))
        if result != row["mentions_poc"]:
            conn.execute("UPDATE articles SET mentions_poc = ? WHERE id = ?", (result, row["id"]))
            changed += 1
    conn.commit()
    return changed


def backfill_exploited_in_wild(conn: sqlite3.Connection, evidence_fn) -> dict:
    """Rescans stored articles for reported real-world exploitation, writing
    both the per-CVE claims and the article-level flag.

    Same shape as backfill_poc_mentions and for the same reason: this was
    added on 22 September 2026, after thousands of real articles already
    existed, and re-running it after tuning the pattern has to be able to
    remove a false positive as well as add a true one -- so each article's
    previous claims are cleared before its current ones are written."""
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


# Sources whose ingesters attach exactly one CVE per article on purpose
# (kev.py, ghsa.py) and never run the text extractor, so a text re-scan must
# leave them alone. Names must match their db.upsert_source() calls.
STRUCTURED_SOURCES = ("CISA KEV", "GitHub Security Advisories")


def backfill_cve_mentions(conn: sqlite3.Connection, extract_fn, high_ticket_fn) -> dict:
    """Re-scan stored articles with the current CVE extractor and add any
    mention it now finds that isn't stored yet.

    Added 23 September 2026 when the extractor learned typographic dashes and
    lowercase. Unlike the flag backfills above, this only ever adds: an
    existing mention (and its CVSS score) is never deleted or rewritten, and
    high_ticket is only ever raised, same as refresh_high_ticket_from_scores.
    Reads the same text ingest does (full_text, else description) and skips
    STRUCTURED_SOURCES."""
    existing: dict[int, set[str]] = {}
    for row in conn.execute("SELECT article_id, cve_id FROM cve_mentions"):
        existing.setdefault(row["article_id"], set()).add(row["cve_id"])
    rows = conn.execute(
        "SELECT a.id, a.description, a.full_text, a.high_ticket FROM articles a "
        "JOIN sources s ON s.id = a.source_id "
        f"WHERE s.name NOT IN ({', '.join('?' for _ in STRUCTURED_SOURCES)})",
        STRUCTURED_SOURCES,
    ).fetchall()
    stats = {"mentions_added": 0, "articles_changed": 0, "promoted_high_ticket": 0, "cves": set()}
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
        if not row["high_ticket"] and high_ticket_fn(new):
            conn.execute("UPDATE articles SET high_ticket = 1 WHERE id = ?", (row["id"],))
            stats["promoted_high_ticket"] += 1
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
    """Real content only -- an article with no full text and no real
    description has nothing for the model to classify against."""
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
    """Real full-text search via SQLite FTS5, ranked by relevance (FTS5's
    own bm25-based `rank`) rather than by date -- a search result set
    should surface the best match first, unlike every other view in this
    app, which is chronological.

    Malformed FTS5 query syntax (an unmatched quote, a bare operator
    character) is caught and retried as one literal quoted phrase instead
    of erroring the whole search over ordinary punctuation a user might
    reasonably type into a search box.
    """
    sql = (
        "SELECT a.* FROM articles a JOIN articles_fts f ON f.rowid = a.id "
        "WHERE articles_fts MATCH ? ORDER BY rank LIMIT ?"
    )
    try:
        return conn.execute(sql, (query, limit)).fetchall()
    except sqlite3.OperationalError:
        phrase = '"' + query.replace('"', '""') + '"'
        return conn.execute(sql, (phrase, limit)).fetchall()


def cves_needing_poc_check(conn: sqlite3.Connection, recheck_after_hours: int) -> list[str]:
    """Every real CVE NekoCTI has already captured, that either hasn't
    been checked against the real PoC-in-GitHub lookup yet, or was last
    checked long enough ago that a new PoC might have appeared since --
    a CVE with zero public PoCs today can genuinely get one added later,
    so "checked once" isn't checked forever, just not re-checked on every
    single run."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=recheck_after_hours)).isoformat()
    rows = conn.execute(
        "SELECT DISTINCT cm.cve_id FROM cve_mentions cm "
        "LEFT JOIN poc_checks pc ON pc.cve_id = cm.cve_id "
        "WHERE pc.cve_id IS NULL OR pc.checked_at < ?",
        (cutoff,),
    ).fetchall()
    return [r["cve_id"] for r in rows]


def replace_cve_pocs(conn: sqlite3.Connection, cve_id: str, pocs: list[dict]) -> None:
    """Replaces this CVE's known PoC repos with the real current set from
    the lookup (a repo's star count changes over time, and a repo can be
    deleted/made private) and marks the CVE as checked just now, whether
    or not any real PoCs were found -- both are real, meaningful
    outcomes."""
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
        "INSERT INTO poc_checks (cve_id, checked_at) VALUES (?, ?) "
        "ON CONFLICT(cve_id) DO UPDATE SET checked_at = excluded.checked_at",
        (cve_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def all_cve_ids(conn: sqlite3.Connection) -> list[str]:
    """Every distinct CVE NekoCTI has captured, newest identifier first so a
    limited enrichment run reaches this year's CVEs before older ones."""
    rows = conn.execute(
        "SELECT DISTINCT cve_id FROM cve_mentions ORDER BY cve_id DESC"
    ).fetchall()
    return [r["cve_id"] for r in rows]


def cves_needing_nvd(conn: sqlite3.Connection, recheck_after_days: int, limit: int) -> list[str]:
    """CVEs to ask NVD about next, in triage order rather than database
    order, because NVD is rate-limited (5 requests per 30s without a key,
    50 with one) and a run is always bounded by `limit`. Order: articles
    already flagged high ticket, then CVEs matching the vendor watchlist,
    then anything with no severity at all, then newest first. Never-checked
    CVEs come before re-checks; a CVE analysed by NVD rarely changes, so
    re-checks are slow (`recheck_after_days`) and only matter for entries
    still awaiting analysis."""
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
    """EPSS is recomputed daily by FIRST.org and comes back in batches, so
    every captured CVE is refreshed rather than a prioritised subset."""
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
    """Stores what NVD says about one CVE. `data` is None when NVD genuinely
    has no record (a reserved or withdrawn identifier): that is still a real
    answer, so the check timestamp is written and the score columns are left
    empty, rather than retrying it on every future run."""
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
    """Marks every captured CVE present in CISA's catalog, and clears the
    flag on any that is not, so a stale flag can't survive a catalog change.
    Only CVEs NekoCTI has actually captured are touched."""
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


def get_freshness(conn: sqlite3.Connection) -> dict:
    """How current the data actually is, for the dashboard's own header.

    The archive is deliberately never pruned (Neko's call, 22 September
    2026: at ~27MB it costs nothing, and old coverage is still evidence).
    Freshness is therefore about the facts being re-checked, not about
    throwing rows away, so this reports when each lookup last ran and how
    much is still waiting."""
    one = lambda sql: conn.execute(sql).fetchone()[0]
    return {
        "last_article_fetched_at": one("SELECT MAX(fetched_at) FROM articles"),
        "last_epss_at": one("SELECT MAX(epss_checked_at) FROM cve_scores"),
        "epss_data_date": one("SELECT MAX(epss_date) FROM cve_scores"),
        "last_kev_at": one("SELECT MAX(kev_checked_at) FROM cve_scores"),
        "last_nvd_at": one("SELECT MAX(nvd_checked_at) FROM cve_scores"),
        "cves_total": one("SELECT COUNT(DISTINCT cve_id) FROM cve_mentions"),
        "cves_awaiting_nvd": one(
            "SELECT COUNT(DISTINCT cm.cve_id) FROM cve_mentions cm "
            "LEFT JOIN cve_scores cs ON cs.cve_id = cm.cve_id "
            "WHERE cs.nvd_checked_at IS NULL"),
        "cves_with_severity": one("SELECT COUNT(*) FROM cve_scores WHERE nvd_base_score IS NOT NULL"),
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


def refresh_high_ticket_from_scores(conn: sqlite3.Connection, epss_percentile_floor: float) -> int:
    """Re-flags articles as high ticket using facts the ingest-time rule
    could not see:
      - the article reports real exploitation in the wild
      - a CVE it mentions is in CISA KEV (confirmed exploitation)
      - NVD's official base score is 9.0+ (most captured CVEs never had a
        score in the article text at all)
      - a CVE it mentions is at or above the EPSS percentile floor
        (predicted exploitation)
    Only ever promotes an article; it never clears a flag another rule set."""
    cur = conn.execute(
        """
        UPDATE articles SET high_ticket = 1
        WHERE high_ticket = 0 AND (
            exploited_in_wild = 1
            OR id IN (SELECT article_id FROM cve_exploit_reports)
            OR id IN (
                SELECT cm.article_id FROM cve_mentions cm
                JOIN cve_scores cs ON cs.cve_id = cm.cve_id
                WHERE cs.kev_listed = 1
                   OR cs.nvd_base_score >= 9.0
                   OR cs.epss_percentile >= ?
            )
        )
        """,
        (epss_percentile_floor,),
    )
    conn.commit()
    return cur.rowcount


def get_pocs_summary(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """One row per real CVE with at least one known public PoC, ranked by
    how credible/active the most-starred repo looks -- a raw PoC count
    alone doesn't distinguish one well-maintained exploit from five
    abandoned forks of the same thing."""
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
    """The exact same focused-article scoping the POCS tab's mention-only
    signal uses (see server.py's get_pocs_overview) - kept here too so the
    ATT&CK classification pass targets the identical real CVE set Neko
    sees in that tab, not a looser approximation."""
    rows = conn.execute(
        "SELECT DISTINCT cm.cve_id FROM cve_mentions cm JOIN articles a ON a.id = cm.article_id "
        "WHERE a.mentions_poc = 1 "
        "AND (SELECT COUNT(DISTINCT cm2.cve_id) FROM cve_mentions cm2 "
        "     WHERE cm2.article_id = a.id) <= 5"
    ).fetchall()
    return {r["cve_id"] for r in rows}


def get_cve_title(conn: sqlite3.Connection, cve_id: str) -> str | None:
    """Real vulnerability description for a CVE, not the bare ID: a GHSA
    advisory's own title already IS the description (see ghsa.py's
    real_title()), preferred over any other article that just mentions the
    CVE in passing. Falls back to the most recent article's title."""
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
    evidence, source_url) - the latter three are None for the LLM tier,
    which has no mapping_type/citation to offer, only a technique guess."""
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
    """Real POCS-tab-eligible CVEs (a real public repo, or a focused
    non-roundup mention) not yet covered by either confidence tier -
    the expert pass always runs first, so anything left here genuinely
    has no expert mapping available."""
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
    """Bulk fetch for the POCS overview list, avoiding one query per row."""
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
