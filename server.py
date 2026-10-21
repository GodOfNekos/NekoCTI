# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""NekoCTI dashboard backend: Python's standard-library HTTP server, bound
to 127.0.0.1 unless NEKOCTI_BIND says otherwise (the container image sets
0.0.0.0 so Docker can publish it; docker-compose.yml then publishes it on the
host's loopback only). Reuses db.py and extract.py for all data access.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, unquote

import attack
import auth
import coverage
import cverecord
import db
import enrich
import extract
import ingest

HERE = Path(__file__).resolve().parent
PORT = 8778
BIND = os.environ.get("NEKOCTI_BIND", "127.0.0.1")

RANGE_HOURS = {"24h": 24, "7d": 24 * 7, "all": None}


def _cutoff_iso(range_key: str) -> str | None:
    hours = RANGE_HOURS.get(range_key, 24)
    if hours is None:
        return None
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def _cve_payload(cve_id: str, article_cvss, score_row, report_count: int,
                 affected: list[tuple[str, str]] | None = None,
                 coverage_rows: list[dict] | None = None, poc_flags: tuple[bool, bool] = (False, False)) -> dict:
    """One CVE for the dashboard: the article's claimed score, NVD's, the CVE
    record's (the CNA's or CISA's, labelled), SSVC, the affected products,
    the two exploitation signals, KEV (confirmed) and EPSS (predicted), and
    exploit maturity with the Nuclei, Metasploit and Sigma links behind it.
    `exploit_reports` counts captured articles reporting it exploited."""
    s = score_row
    ssvc = {k: s[f"ssvc_{k}"] for k in ("exploitation", "automatable", "technical_impact")} if s else {}
    coverage_rows = coverage_rows or []
    kinds = {r["kind"] for r in coverage_rows}
    maturity = coverage.exploit_maturity(bool(s and s["kev_listed"]), report_count > 0, kinds, *poc_flags)
    return {
        "maturity": maturity,
        # A few links per kind is plenty; Nuclei has dozens for some CVEs.
        "coverage": [r for k in ("metasploit", "nuclei", "sigma")
                     for r in [x for x in coverage_rows if x["kind"] == k][:3]],
        "id": cve_id,
        "cvss": article_cvss,
        "nvd_cvss": s["nvd_base_score"] if s else None,
        "nvd_severity": s["nvd_severity"] if s else None,
        "nvd_version": s["nvd_cvss_version"] if s else None,
        "rec_cvss": s["rec_base_score"] if s else None,
        "rec_severity": s["rec_severity"] if s else None,
        "rec_source": s["rec_score_source"] if s else None,
        "ssvc": ssvc if any(ssvc.values()) else None,
        "affected": [" ".join(filter(None, pair)) for pair in (affected or [])][:5],
        "cwes": (s["nvd_cwes"] or s["rec_cwes"]) if s else None,
        "kev": bool(s["kev_listed"]) if s else False,
        "kev_date": s["kev_date_added"] if s else None,
        "kev_ransomware": (s["kev_ransomware"] if s else None),
        "epss": s["epss_score"] if s else None,
        "epss_percentile": s["epss_percentile"] if s else None,
        "epss_date": s["epss_date"] if s else None,
        # EPSS is recalculated daily, so an old score is marked, never hidden.
        "epss_stale": _is_stale(s["epss_date"]) if s else False,
        "exploit_reports": report_count,
    }


def _is_stale(epss_date: str | None) -> bool:
    if not epss_date:
        return False
    try:
        d = datetime.fromisoformat(epss_date).date()
    except ValueError:
        return False
    return (datetime.now(timezone.utc).date() - d).days > enrich.EPSS_STALE_AFTER_DAYS


def _http_url(url: str, base: str = "") -> str | None:
    """url made absolute against base, if it's http(s); else None. Feeds hand
    over relative image paths and, in principle, javascript: links."""
    if not url:
        return None
    full = urljoin(base, url)
    return full if urlparse(full).scheme in ("http", "https") else None


def _serialize_article(conn, row, include_body: bool = False) -> dict:
    cves = conn.execute(
        "SELECT cve_id, cvss_score FROM cve_mentions WHERE article_id = ?",
        (row["id"],),
    ).fetchall()
    vendors = conn.execute(
        "SELECT DISTINCT vendor_term FROM vendor_matches WHERE article_id = ?",
        (row["id"],),
    ).fetchall()
    entities = conn.execute(
        "SELECT DISTINCT entity_name FROM entity_matches WHERE article_id = ?",
        (row["id"],),
    ).fetchall()
    campaigns = conn.execute(
        "SELECT DISTINCT campaign_name FROM campaign_matches WHERE article_id = ?",
        (row["id"],),
    ).fetchall()
    # The article's own claimed score stays as `cvss`, apart from NVD's.
    _cve_ids = [c["cve_id"] for c in cves]
    _scores = db.get_cve_scores(conn, _cve_ids)
    _reports = db.get_exploit_reports(conn, _cve_ids)
    _affected = db.get_cve_affected(conn, _cve_ids)
    _coverage = db.get_cve_coverage(conn, _cve_ids)
    _poc = db.get_poc_flags(conn, _cve_ids)
    data = {
        "id": row["id"],
        "title": row["title"],
        "link": _http_url(row["link"]),
        "published_at": row["published_at"],
        "fetched_at": row["fetched_at"],
        "high_ticket": bool(row["high_ticket"]),
        "priority_band": row["priority_band"] or "NONE",
        "priority_score": row["priority_score"],
        "priority_why": json.loads(row["priority_why"] or "[]"),
        "is_breach": bool(row["is_breach"]),
        "mentions_poc": bool(row["mentions_poc"]),
        "exploited_in_wild": bool(row["exploited_in_wild"]),
        "cves": [_cve_payload(c["cve_id"], c["cvss_score"], _scores.get(c["cve_id"]),
                              _reports.get(c["cve_id"], 0), _affected.get(c["cve_id"]),
                              _coverage.get(c["cve_id"]), _poc.get(c["cve_id"], (False, False))) for c in cves],
        "vendors": [v["vendor_term"] for v in vendors],
        "entities": [e["entity_name"] for e in entities],
        "campaigns": [c["campaign_name"] for c in campaigns],
    }
    if include_body:
        # The fetched full text, else the feed or KEV description: the
        # dashboard is where articles are read.
        data["body"] = row["full_text"] or row["description"] or "(no content captured)"
        images = conn.execute(
            "SELECT image_url FROM article_images WHERE article_id = ? ORDER BY position",
            (row["id"],),
        ).fetchall()
        data["images"] = [u for i in images if (u := _http_url(i["image_url"], row["link"]))]
    return data


_TAB_FILTERS = {
    "high_ticket": ["high_ticket = 1"],
    # Every watchlist match, high ticket or not (Neko, 19 October 2026).
    "watchlist": ["EXISTS (SELECT 1 FROM vendor_matches v WHERE v.article_id = articles.id)"],
    "entities": ["EXISTS (SELECT 1 FROM entity_matches e WHERE e.article_id = articles.id)"],
    "campaigns": ["EXISTS (SELECT 1 FROM campaign_matches c WHERE c.article_id = articles.id)"],
    "breaches": ["is_breach = 1"],
    "archive": [],
}


def search_articles(query: str) -> dict:
    conn = db.connect()
    try:
        rows = db.search_articles(conn, query)
        return {
            "query": query,
            "articles": [_serialize_article(conn, r) for r in rows],
        }
    finally:
        conn.close()


def get_articles(tab: str, range_key: str) -> dict:
    conn = db.connect()
    try:
        cutoff = _cutoff_iso(range_key)
        where = list(_TAB_FILTERS.get(tab, []))
        params: list = []
        if cutoff:
            where.append("fetched_at >= ?")
            params.append(cutoff)

        clause = f"WHERE {' AND '.join(where)}" if where else ""
        # HIGH TICKET is a priority list: strongest band first, newest first
        # within it (the score's nudges reward articles that mention a lot,
        # which isn't the same as mattering more). The rest read by date.
        order = "priority_score / 100 DESC, published_at DESC" if tab == "high_ticket" else "published_at DESC"
        rows = conn.execute(
            f"SELECT * FROM articles {clause} ORDER BY {order} LIMIT 300",
            params,
        ).fetchall()

        counts = {}
        for key, filters in _TAB_FILTERS.items():
            count_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
            c = conn.execute(f"SELECT COUNT(*) c FROM articles {count_clause}").fetchone()
            counts[key] = c["c"]

        return {
            "articles": [_serialize_article(conn, r) for r in rows],
            "counts": counts,
        }
    finally:
        conn.close()


def get_article_detail(article_id: int) -> dict | None:
    conn = db.connect()
    try:
        row = conn.execute("SELECT * FROM articles WHERE id = ?", (article_id,)).fetchone()
        if row is None:
            return None
        return _serialize_article(conn, row, include_body=True)
    finally:
        conn.close()


def get_attack_matrix() -> dict:
    """Tactics x techniques from MITRE's data, with how many articles map to
    each technique. Unmatched techniques are included so the whole framework
    shows."""
    catalog = attack.get_technique_catalog()
    tactics = attack.get_tactics()

    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT technique_id, COUNT(DISTINCT article_id) c FROM attack_techniques GROUP BY technique_id"
        ).fetchall()
        counts = {r["technique_id"]: r["c"] for r in rows}
    finally:
        conn.close()

    techniques = {
        tid: {"name": info["name"], "tactics": info["tactics"], "count": counts.get(tid, 0)}
        for tid, info in catalog.items()
    }
    return {"tactics": tactics, "techniques": techniques}


def get_attack_technique_articles(technique_id: str) -> dict:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT a.* FROM articles a "
            "JOIN attack_techniques t ON t.article_id = a.id "
            "WHERE t.technique_id = ? ORDER BY a.published_at DESC",
            (technique_id,),
        ).fetchall()
        catalog = attack.get_technique_catalog()
        info = catalog.get(technique_id, {"name": technique_id, "tactics": []})
        return {
            "technique_id": technique_id,
            "technique_name": info["name"],
            "articles": [_serialize_article(conn, r) for r in rows],
        }
    finally:
        conn.close()


def get_entity_articles(entity_name: str) -> dict:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT DISTINCT a.* FROM articles a "
            "JOIN entity_matches e ON e.article_id = a.id "
            "WHERE e.entity_name = ? ORDER BY a.published_at DESC",
            (entity_name,),
        ).fetchall()
        return {
            "entity_name": entity_name,
            "articles": [_serialize_article(conn, r) for r in rows],
        }
    finally:
        conn.close()


def get_pocs_overview() -> dict:
    """CVEs with either kind of PoC evidence, labelled: a public GitHub repo
    (nomi-sec/PoC-in-GitHub), or coverage that describes a PoC. mentions_poc
    is an article-level flag, so a mention only counts from articles naming
    5 or fewer CVEs; roundups cover 50 to 600."""
    conn = db.connect()
    try:
        repo_rows = {r["cve_id"]: r for r in db.get_pocs_summary(conn)}
        mention_rows = conn.execute(
            "SELECT cm.cve_id, COUNT(DISTINCT a.id) mention_count "
            "FROM cve_mentions cm JOIN articles a ON a.id = cm.article_id "
            "WHERE a.mentions_poc = 1 "
            "AND (SELECT COUNT(DISTINCT cm2.cve_id) FROM cve_mentions cm2 "
            "     WHERE cm2.article_id = a.id) <= 5 "
            "GROUP BY cm.cve_id"
        ).fetchall()
        mention_counts = {r["cve_id"]: r["mention_count"] for r in mention_rows}

        cve_ids = set(repo_rows) | set(mention_counts)
        attack_techniques = db.get_cve_attack_techniques_bulk(conn, list(cve_ids))
        score_rows = db.get_cve_scores(conn, list(cve_ids))
        report_counts = db.get_exploit_reports(conn, list(cve_ids))
        affected = db.get_cve_affected(conn, list(cve_ids))
        coverage_rows = db.get_cve_coverage(conn, list(cve_ids))
        poc_flags = db.get_poc_flags(conn, list(cve_ids))
        # From each CVE's own record, not every vendor its articles named.
        vendor_terms = cverecord.watchlist_terms(conn, list(cve_ids), extract.load_filters()[0])
        cves = []
        for cve_id in cve_ids:
            cvss_row = conn.execute(
                "SELECT cvss_score FROM cve_mentions WHERE cve_id = ? AND cvss_score IS NOT NULL LIMIT 1",
                (cve_id,),
            ).fetchone()
            article_count = conn.execute(
                "SELECT COUNT(DISTINCT article_id) c FROM cve_mentions WHERE cve_id = ?",
                (cve_id,),
            ).fetchone()
            # A GHSA advisory's title is the vulnerability description, so
            # it's preferred over any article that mentions the CVE.
            title_row = conn.execute(
                "SELECT a.title, a.published_at FROM cve_mentions cm "
                "JOIN articles a ON a.id = cm.article_id "
                "JOIN sources s ON s.id = a.source_id "
                "WHERE cm.cve_id = ? "
                "ORDER BY (s.name = 'GitHub Security Advisories') DESC, a.published_at DESC "
                "LIMIT 1",
                (cve_id,),
            ).fetchone()
            latest_row = conn.execute(
                "SELECT MAX(a.published_at) latest FROM cve_mentions cm "
                "JOIN articles a ON a.id = cm.article_id WHERE cm.cve_id = ?",
                (cve_id,),
            ).fetchone()
            repo = repo_rows.get(cve_id)
            latest_activity_at = max(
                filter(None, [latest_row["latest"], repo["latest_pushed_at"] if repo else None]),
                default=None,
            )
            cves.append({
                "cve_id": cve_id,
                "title": title_row["title"] if title_row else None,
                "vendors": vendor_terms.get(cve_id, [])[:5],
                "has_public_repo": repo is not None,
                "poc_count": repo["poc_count"] if repo else 0,
                "max_stars": repo["max_stars"] if repo else 0,
                "latest_pushed_at": repo["latest_pushed_at"] if repo else None,
                "latest_activity_at": latest_activity_at,
                "mention_count": mention_counts.get(cve_id, 0),
                "cvss": cvss_row["cvss_score"] if cvss_row else None,
                "article_count": article_count["c"],
                "attack_techniques": attack_techniques.get(cve_id, []),
                **{k: v for k, v in _cve_payload(
                    cve_id, cvss_row["cvss_score"] if cvss_row else None,
                    score_rows.get(cve_id), report_counts.get(cve_id, 0), affected.get(cve_id),
                    coverage_rows.get(cve_id), poc_flags.get(cve_id, (False, False)),
                ).items() if k not in ("id", "cvss")},
            })
        cves.sort(key=lambda c: c["latest_activity_at"] or "", reverse=True)
        return {"cves": cves}
    finally:
        conn.close()


def get_poc_detail(cve_id: str) -> dict:
    conn = db.connect()
    try:
        pocs = db.get_pocs_for_cve(conn, cve_id)
        articles = conn.execute(
            "SELECT DISTINCT a.* FROM articles a JOIN cve_mentions cm ON cm.article_id = a.id "
            "WHERE cm.cve_id = ? ORDER BY a.published_at DESC",
            (cve_id,),
        ).fetchall()
        return {
            "cve_id": cve_id,
            "pocs": [
                {
                    "repo_full_name": p["repo_full_name"],
                    "repo_url": p["repo_url"],
                    "description": p["description"],
                    "stars": p["stars"],
                    "repo_created_at": p["repo_created_at"],
                    "repo_pushed_at": p["repo_pushed_at"],
                }
                for p in pocs
            ],
            "attack_techniques": [
                {
                    "technique_id": t["technique_id"],
                    "technique_name": t["technique_name"],
                    "confidence": t["confidence"],
                    "mapping_type": t["mapping_type"],
                    "evidence": t["evidence"],
                    "source_url": t["source_url"],
                }
                for t in db.get_cve_attack_techniques(conn, cve_id)
            ],
            "articles": [_serialize_article(conn, r) for r in articles],
        }
    finally:
        conn.close()


def get_campaign_articles(campaign_name: str) -> dict:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT DISTINCT a.* FROM articles a "
            "JOIN campaign_matches c ON c.article_id = a.id "
            "WHERE c.campaign_name = ? ORDER BY a.published_at DESC",
            (campaign_name,),
        ).fetchall()
        return {
            "campaign_name": campaign_name,
            "articles": [_serialize_article(conn, r) for r in rows],
        }
    finally:
        conn.close()


# The editable configs, by URL: file and the one key it holds.
_CONFIGS = {
    "/api/watchlist": ("watchlist.json", "vendors"),
    "/api/tags": ("tags.json", "entities"),
    "/api/campaigns": ("campaigns.json", "campaigns"),
}
MAX_CONFIG_BYTES = 256 * 1024


def read_config(url_path: str) -> dict:
    name, key = _CONFIGS[url_path]
    path = HERE / name
    # Missing or empty (a fresh container's entrypoint creates empty files):
    # nothing configured yet.
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    if not text.strip():
        return {key: {} if key == "vendors" else []}
    return json.loads(text)


def valid_config(url_path: str, data) -> bool:
    """The shape extract.py relies on; anything else would break every later
    ingest. Watchlist: {"vendors": {category: [entry, ...]}}, an entry being a
    term or {"term": str, "exclude": [str, ...]}. Tags and campaigns:
    {key: [{"name": str, "aliases": [str, ...]}, ...]}."""
    _, key = _CONFIGS[url_path]
    if not isinstance(data, dict) or set(data) != {key}:
        return False
    strs = lambda xs: isinstance(xs, list) and all(isinstance(x, str) for x in xs)
    if key == "vendors":
        def entry_ok(e) -> bool:
            if isinstance(e, str):
                return True
            return (isinstance(e, dict) and set(e) <= {"term", "exclude"}
                    and isinstance(e.get("term"), str) and bool(e["term"].strip())
                    and strs(e.get("exclude", [])) and all(x.strip() for x in e.get("exclude", [])))
        return isinstance(data[key], dict) and all(
            isinstance(k, str) and isinstance(v, list) and all(entry_ok(e) for e in v)
            for k, v in data[key].items())
    return isinstance(data[key], list) and all(
        isinstance(e, dict) and isinstance(e.get("name"), str) and e["name"].strip()
        and strs(e.get("aliases", [])) and set(e) <= {"name", "aliases"}
        for e in data[key])


def write_config(url_path: str, data: dict) -> None:
    (HERE / _CONFIGS[url_path][0]).write_text(json.dumps(data, indent=2), encoding="utf-8")


# --- Run check now ---
# A background thread runs the ingest so the request returns at once, and a
# lock stops two runs overlapping.

_ingest_lock = threading.Lock()
_ingest_state: dict = {
    "running": False,
    "started_at": None,
    "finished_at": None,
    "results": None,
    "error": None,
}


def _run_ingest_job() -> None:
    try:
        results = ingest.run_all()
        # Then re-check the facts (EPSS, KEV, new CVEs' severity), so the
        # dashboard is current, not just longer. A failure here is reported
        # separately and never loses a successful ingest.
        enrich_summary, enrich_error = None, None
        try:
            conn = db.connect()
            try:
                enrich_summary = enrich.refresh_after_ingest(conn)
            finally:
                conn.close()
        except Exception as e:
            enrich_error = str(e)
        with _ingest_lock:
            _ingest_state["results"] = results
            _ingest_state["enrich"] = enrich_summary
            _ingest_state["enrich_error"] = enrich_error
            _ingest_state["error"] = None
    except Exception as e:
        with _ingest_lock:
            _ingest_state["error"] = str(e)
    finally:
        with _ingest_lock:
            _ingest_state["running"] = False
            _ingest_state["finished_at"] = datetime.now(timezone.utc).isoformat()


def start_ingest_run() -> bool:
    """False, starting nothing, if a run is already going. Server-side, so a
    second tab or a retried request can't start a second run."""
    with _ingest_lock:
        if _ingest_state["running"]:
            return False
        _ingest_state["running"] = True
        _ingest_state["started_at"] = datetime.now(timezone.utc).isoformat()
        _ingest_state["finished_at"] = None
        _ingest_state["results"] = None
        _ingest_state["error"] = None
    threading.Thread(target=_run_ingest_job, daemon=True).start()
    return True


def get_ingest_status() -> dict:
    with _ingest_lock:
        state = dict(_ingest_state)
    conn = db.connect()
    try:
        state["freshness"] = db.get_freshness(conn)
    finally:
        conn.close()
    return state


_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".ttf": "font/ttf",
}

# The only files the page needs, by URL path; everything else is a 404. The
# app folder also holds the database and, in the container, data/, which can
# hold private keys (an early version served it, fixed 30 September 2026).
_STATIC_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/style.css": "style.css",
    "/app.js": "app.js",
    "/fonts/ShareTechMono-Regular.ttf": "fonts/ShareTechMono-Regular.ttf",
    "/login": "login.html",
    "/login.js": "login.js",
}

# Everything else needs a login session (auth.py).
PUBLIC_PATHS = {"/login", "/login.js", "/style.css", "/fonts/ShareTechMono-Regular.ttf"}
SESSION_COOKIE = "nekocti_session"
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]*")   # secrets.token_urlsafe's alphabet
MAX_LOGIN_BYTES = 1024

# On every response. Feed text is untrusted, so the page may only run its own
# script and style; images may come from any https source.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' https: data:; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}

# Every write must carry this header. A plain cross-site form or fetch can't
# add one without a CORS preflight, which this server never answers.
WRITE_HEADER = "X-NekoCTI"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        """One line per request to stderr (the container log): who (a
        proxy's user header, such as Tailscale Serve's, when there is one),
        from which address, what. Never bodies."""
        headers = getattr(self, "headers", None) or {}   # absent on a malformed request line
        who = headers.get("Tailscale-User-Login", "-")
        where = headers.get("X-Forwarded-For", self.client_address[0])
        sys.stderr.write(f"{self.log_date_time_string()} {where} {who} {fmt % args}\n")

    def end_headers(self) -> None:
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        super().end_headers()

    def _write_allowed(self) -> bool:
        if self.headers.get(WRITE_HEADER) == "1":
            return True
        self.send_error(403, "missing write header")
        return False

    def _json(self, payload: dict, status: int = 200, cookie: str | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    # --- login (auth.py) ---

    def _session_token(self) -> str | None:
        try:
            morsel = SimpleCookie(self.headers.get("Cookie", "")).get(SESSION_COOKIE)
        except CookieError:
            return None
        return morsel.value if morsel else None

    def _logged_in(self, path: str) -> bool:
        """Let the request through, or answer it: API calls get 401 and
        pages go to the login page."""
        if path in PUBLIC_PATHS or auth.session_valid(self._session_token()):
            return True
        if path.startswith("/api/"):
            self._json({"error": "login required"}, status=401)
        else:
            self.send_response(303)
            self.send_header("Location", "/login")
            self.send_header("Content-Length", "0")
            self.end_headers()
        return False

    @staticmethod
    def _cookie(token: str, max_age: int) -> str:
        # HttpOnly: no script can read it. SameSite=Strict: no other site's
        # request carries it. Secure: HTTPS only (localhost counts in Dev).
        # Only a token_urlsafe value (or "" to log out) may reach the header:
        # a line break would split the response, and ; or = would set
        # attributes. Refused, not stripped, so a bug fails loudly.
        if not _TOKEN_RE.fullmatch(token) or not isinstance(max_age, int):
            raise ValueError("not a session token")
        return f"{SESSION_COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"

    def _login(self) -> None:
        if not self._write_allowed():
            return
        if not auth.password_is_set():
            self._json({"error": "no password set - run `main.py set-password` first"}, status=503)
            return
        if auth.locked_out():
            self._json({"error": "too many wrong passwords - try again in 15 minutes"}, status=429)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_LOGIN_BYTES:
            self.send_error(400)
            return
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            body = None
        password = body.get("password") if isinstance(body, dict) else None
        if not isinstance(password, str) or not auth.check_password(password):
            self._json({"error": "wrong password"}, status=401)
            return
        self._json({"ok": True}, cookie=self._cookie(auth.create_session(), auth.SESSION_SECONDS))

    def _logout(self) -> None:
        if not self._write_allowed():
            return
        auth.end_session(self._session_token())
        self._json({"ok": True}, cookie=self._cookie("", 0))

    def _static(self, rel_path: str) -> None:
        path = HERE / rel_path
        if not path.is_file():
            self.send_error(404)
            return
        content_type = _STATIC_TYPES.get(path.suffix, "application/octet-stream")
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if not self._logged_in(parsed.path):
            return
        qs = parse_qs(parsed.query)

        if parsed.path == "/api/articles":
            tab = (qs.get("tab") or ["high_ticket"])[0]
            range_key = (qs.get("range") or ["24h"])[0]
            self._json(get_articles(tab, range_key))
            return
        if parsed.path == "/api/search":
            query = (qs.get("q") or [""])[0].strip()
            self._json(search_articles(query) if query else {"query": "", "articles": []})
            return
        if parsed.path.startswith("/api/article/"):
            try:
                article_id = int(parsed.path.rsplit("/", 1)[-1])
            except ValueError:
                self.send_error(400)
                return
            detail = get_article_detail(article_id)
            if detail is None:
                self.send_error(404)
                return
            self._json(detail)
            return
        if parsed.path in _CONFIGS:
            self._json(read_config(parsed.path))
            return
        if parsed.path == "/api/attack/matrix":
            self._json(get_attack_matrix())
            return
        if parsed.path.startswith("/api/attack/technique/"):
            technique_id = parsed.path.rsplit("/", 1)[-1]
            self._json(get_attack_technique_articles(technique_id))
            return
        if parsed.path.startswith("/api/entity/"):
            entity_name = unquote(parsed.path[len("/api/entity/"):])
            self._json(get_entity_articles(entity_name))
            return
        if parsed.path.startswith("/api/campaign/"):
            campaign_name = unquote(parsed.path[len("/api/campaign/"):])
            self._json(get_campaign_articles(campaign_name))
            return
        if parsed.path == "/api/ingest/status":
            self._json(get_ingest_status())
            return
        if parsed.path == "/api/pocs":
            self._json(get_pocs_overview())
            return
        if parsed.path.startswith("/api/poc/"):
            cve_id = unquote(parsed.path[len("/api/poc/"):])
            self._json(get_poc_detail(cve_id))
            return

        rel = _STATIC_FILES.get(parsed.path)
        if rel:
            self._static(rel)
        else:
            self.send_error(404)

    def do_PUT(self) -> None:
        if not self._logged_in(urlparse(self.path).path):
            return
        if self.path not in _CONFIGS:
            self.send_error(404)
            return
        if not self._write_allowed():
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_CONFIG_BYTES:
            self.send_error(413 if length > MAX_CONFIG_BYTES else 400)
            return
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            body = None
        if not valid_config(self.path, body):
            self.send_error(400, "not a valid config")
            return
        write_config(self.path, body)
        self._json({"ok": True})

    def do_POST(self) -> None:
        if self.path == "/api/login":
            self._login()
            return
        if self.path == "/api/logout":
            self._logout()
            return
        if not self._logged_in(urlparse(self.path).path):
            return
        if self.path == "/api/ingest/run":
            if not self._write_allowed():
                return
            started = start_ingest_run()
            if started:
                self._json({"ok": True, "started": True})
            else:
                self._json({"ok": False, "started": False, "error": "a check is already running"}, status=409)
            return
        self.send_error(404)


def main() -> None:
    db.init_db()
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"NekoCTI dashboard: http://{BIND}:{PORT}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
