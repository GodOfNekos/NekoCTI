"""NekoCTI local dashboard backend.

Python stdlib http.server, no framework - matches the pattern this
environment already uses for 3D Model Terminal's own local backend, and
this environment's broader preference for minimal dependencies. Binds to
127.0.0.1 only: this is a personal, single-user tool, reachable over
Tailscale/localhost like every other internal tool built here, never a
publicly exposed port.

Reuses db.py/extract.py directly rather than reimplementing any of the
data-access logic already proven by the ingestion pipeline.
"""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

import attack
import db
import extract
import ingest

HERE = Path(__file__).resolve().parent
PORT = 8778
BIND = "127.0.0.1"

RANGE_HOURS = {"24h": 24, "7d": 24 * 7, "all": None}


def _cutoff_iso(range_key: str) -> str | None:
    hours = RANGE_HOURS.get(range_key, 24)
    if hours is None:
        return None
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def _cve_payload(cve_id: str, article_cvss, score_row, report_count: int) -> dict:
    """One CVE as the dashboard needs it: what the article claimed, what NVD
    says, and the two separate exploitation signals -- KEV (confirmed, from
    CISA) and EPSS (predicted). `exploit_reports` counts captured articles
    that report this CVE as exploited, which often precedes a KEV entry."""
    s = score_row
    return {
        "id": cve_id,
        "cvss": article_cvss,
        "nvd_cvss": s["nvd_base_score"] if s else None,
        "nvd_severity": s["nvd_severity"] if s else None,
        "nvd_version": s["nvd_cvss_version"] if s else None,
        "cwes": s["nvd_cwes"] if s else None,
        "kev": bool(s["kev_listed"]) if s else False,
        "kev_date": s["kev_date_added"] if s else None,
        "kev_ransomware": (s["kev_ransomware"] if s else None),
        "epss": s["epss_score"] if s else None,
        "epss_percentile": s["epss_percentile"] if s else None,
        "epss_date": s["epss_date"] if s else None,
        # EPSS is recalculated daily, so an old score is a real caveat
        # rather than a fact. Marked, never hidden; the next check refreshes
        # it.
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
    return (datetime.now(timezone.utc).date() - d).days > enrich_stale_days()


def enrich_stale_days() -> int:
    import enrich as enrich_mod
    return enrich_mod.EPSS_STALE_AFTER_DAYS


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
    # Enrichment facts per CVE (enrich.py): official severity, CISA KEV
    # membership (confirmed exploitation) and the EPSS percentile
    # (predicted). The article's own claimed score stays as `cvss`, so the
    # two are never confused.
    _cve_ids = [c["cve_id"] for c in cves]
    _scores = db.get_cve_scores(conn, _cve_ids)
    _reports = db.get_exploit_reports(conn, _cve_ids)
    data = {
        "id": row["id"],
        "title": row["title"],
        "link": row["link"],
        "published_at": row["published_at"],
        "fetched_at": row["fetched_at"],
        "high_ticket": bool(row["high_ticket"]),
        "is_breach": bool(row["is_breach"]),
        "mentions_poc": bool(row["mentions_poc"]),
        "exploited_in_wild": bool(row["exploited_in_wild"]),
        "cves": [_cve_payload(c["cve_id"], c["cvss_score"], _scores.get(c["cve_id"]),
                              _reports.get(c["cve_id"], 0)) for c in cves],
        "vendors": [v["vendor_term"] for v in vendors],
        "entities": [e["entity_name"] for e in entities],
        "campaigns": [c["campaign_name"] for c in campaigns],
    }
    if include_body:
        # Read in-dashboard: the real full-article text when we fetched
        # one (THN), falling back to the RSS/KEV description otherwise --
        # this is what makes the dashboard the actual place to read the
        # content, not just a launchpad to the original site.
        data["body"] = row["full_text"] or row["description"] or "(no content captured)"
        images = conn.execute(
            "SELECT image_url FROM article_images WHERE article_id = ? ORDER BY position",
            (row["id"],),
        ).fetchall()
        data["images"] = [i["image_url"] for i in images]
    return data


_TAB_FILTERS = {
    "high_ticket": ["high_ticket = 1"],
    "watchlist": [
        "high_ticket = 0",
        "EXISTS (SELECT 1 FROM vendor_matches v WHERE v.article_id = articles.id)",
    ],
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
        rows = conn.execute(
            f"SELECT * FROM articles {clause} ORDER BY published_at DESC LIMIT 300",
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
    """Real tactics x techniques structure from MITRE's own data, with a
    real count of how many captured articles map to each technique -- the
    heatmap signal. Techniques with zero real matches still appear (the
    point is seeing the whole framework, not just a filtered list)."""
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
    """Two real, distinct kinds of PoC evidence, not just one: a confirmed
    public GitHub repo (nomi-sec/PoC-in-GitHub) is the strongest signal,
    but real coverage NekoCTI has already ingested can also describe a
    PoC/exploit that was never released as a public repo at all (a
    researcher's own writeup, a privately-sold exploit, a brand-new CVE
    the repo-lookup hasn't caught up to yet) - `extract.mentions_poc`
    catches that from the article text itself. A CVE shows up here if
    either kind of evidence exists, clearly labeled which."""
    conn = db.connect()
    try:
        repo_rows = {r["cve_id"]: r for r in db.get_pocs_summary(conn)}
        # A real over-attribution bug found and fixed here, 16 September
        # 2026: a monthly "Security Update Review" mentioning 621 distinct
        # CVEs had its one real PoC-mention flag naively attributed to
        # every single one of them, since mentions_poc is an article-level
        # flag, not a per-CVE one. A roundup covering hundreds of CVEs
        # can't be confidently tied to any specific one of them, so the
        # mention signal here is scoped to articles discussing a real
        # small, focused set of CVEs (5 or fewer) - a threshold chosen
        # after finding real roundup articles routinely cover 50-600+.
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
        # Severity and exploitation facts for the same set, fetched in two
        # queries rather than per CVE inside the loop below.
        score_rows = db.get_cve_scores(conn, list(cve_ids))
        report_counts = db.get_exploit_reports(conn, list(cve_ids))
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
            # Real vulnerability description, not just the bare CVE ID: a
            # GHSA advisory's own title already IS the vulnerability
            # description (see ghsa.py's real_title()), so that's preferred
            # over any other article that happens to mention the CVE in
            # passing; falls back to the most recent article title if no
            # GHSA record exists for it.
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
            vendor_rows = conn.execute(
                "SELECT DISTINCT v.vendor_term FROM cve_mentions cm "
                "JOIN vendor_matches v ON v.article_id = cm.article_id "
                "WHERE cm.cve_id = ? LIMIT 5",
                (cve_id,),
            ).fetchall()
            repo = repo_rows.get(cve_id)
            latest_activity_at = max(
                filter(None, [latest_row["latest"], repo["latest_pushed_at"] if repo else None]),
                default=None,
            )
            cves.append({
                "cve_id": cve_id,
                "title": title_row["title"] if title_row else None,
                "vendors": [v["vendor_term"] for v in vendor_rows],
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
                    score_rows.get(cve_id), report_counts.get(cve_id, 0),
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


def get_watchlist() -> dict:
    return json.loads((HERE / "watchlist.json").read_text(encoding="utf-8"))


def put_watchlist(data: dict) -> None:
    (HERE / "watchlist.json").write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_tags() -> dict:
    return json.loads((HERE / "tags.json").read_text(encoding="utf-8"))


def put_tags(data: dict) -> None:
    (HERE / "tags.json").write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_campaigns() -> dict:
    path = HERE / "campaigns.json"
    if not path.exists():
        return {"campaigns": []}
    return json.loads(path.read_text(encoding="utf-8"))


def put_campaigns(data: dict) -> None:
    (HERE / "campaigns.json").write_text(json.dumps(data, indent=2), encoding="utf-8")


# --- Manual "run check now" ---
# Real on-demand ingestion from the dashboard itself, Neko's explicit
# request, mirroring TCG Price Tracker's own "Run price check now" button
# - a lock guards against overlapping runs (this app's own ingest is much
# faster than TCG's Playwright-based scraping, but still real network I/O
# across 30+ sources, not instant), and the job runs in a background
# thread so the triggering HTTP request returns immediately rather than
# holding the connection open for however long the real run takes.

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
        # Re-check the facts as well as fetching new articles, so the
        # dashboard is current rather than merely longer: EPSS and the KEV
        # catalog change daily, and CVEs that just arrived have no severity
        # yet. Cheap parts always run; NVD is bounded (see enrich.py).
        # A failure here must not lose a successful ingest, so it is
        # reported separately rather than raised.
        enrich_summary, enrich_error = None, None
        try:
            import enrich as enrich_mod
            conn = db.connect()
            try:
                enrich_summary = enrich_mod.refresh_after_ingest(conn)
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
    """Returns False without starting anything if a run is already in
    progress -- the real overlap guard, not just a UI-side disabled button
    (a second browser tab, or a stale request retried by the client,
    would otherwise still be able to kick off a real second run)."""
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
    ".otf": "font/otf",
}

# The only files the page needs, by URL path. Everything else is a 404: the
# app folder also holds the database and, in the container, data/ with the
# node's Tailscale keys, which the old serve-anything-under-HERE rule handed
# to the whole tailnet (found 30 September 2026).
_STATIC_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/style.css": "style.css",
    "/app.js": "app.js",
    "/fonts/monofonto.otf": "fonts/monofonto.otf",
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep the console readable; real errors still raise

    def _json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
        if parsed.path == "/api/watchlist":
            self._json(get_watchlist())
            return
        if parsed.path == "/api/tags":
            self._json(get_tags())
            return
        if parsed.path == "/api/campaigns":
            self._json(get_campaigns())
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
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")

        if self.path == "/api/watchlist":
            put_watchlist(body)
            self._json({"ok": True})
            return
        if self.path == "/api/tags":
            put_tags(body)
            self._json({"ok": True})
            return
        if self.path == "/api/campaigns":
            put_campaigns(body)
            self._json({"ok": True})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if self.path == "/api/ingest/run":
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
