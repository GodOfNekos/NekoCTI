# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-CVE enrichment for CVEs NekoCTI has already captured, keyed on CVE ID
like pocs.py:

  CVE record -- the CNA's or CISA's score, SSVC and affected products
               (cverecord.py), there before NVD's analysis.
  Coverage  -- Nuclei templates, Metasploit exploit modules and Sigma
               rules per CVE (coverage.py).
  NVD 2.0   -- the official CVSS base score, severity, vector and CWE. One
               CVE per request, rate-limited (5 per 30s unkeyed, 50 with a
               key), so runs are bounded by --limit in triage order.
  EPSS      -- FIRST.org's probability of exploitation in the next 30 days,
               and its percentile. Batched, recomputed daily.
  CISA KEV  -- membership of the Known Exploited Vulnerabilities catalog:
               confirmed exploitation, the strongest signal of the three.

KEV means it is being exploited, EPSS that it probably will be, and a public
PoC (pocs.py) that the code to do it exists.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import coverage
import cverecord
import db
import extract
import priority

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

REQUEST_TIMEOUT_S = 30
EPSS_BATCH_SIZE = 100          # CVEs per request, keeping the URL sane
EPSS_RECHECK_HOURS = 20        # EPSS is recomputed daily
NVD_RECHECK_DAYS = 7           # only for CVEs NVD hasn't finished analysing
NVD_DEFAULT_LIMIT = 200

# Just inside NVD's limits, because being throttled costs more than pacing.
NVD_DELAY_WITH_KEY_S = 0.7
NVD_DELAY_NO_KEY_S = 6.5


def get_json(url: str, headers: dict | None = None, timeout: float = REQUEST_TIMEOUT_S):
    """GET and parse JSON. Every API module fetches through this; HTTP errors
    propagate so callers can tell a 404 from a failure."""
    req = urllib.request.Request(url, headers={"User-Agent": "NekoCTI", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def github_headers() -> dict:
    """For GitHub's REST API (advisories, repository listings). 60 requests an
    hour unauthenticated; GITHUB_TOKEN raises that to 5,000 if it's set."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def nvd_api_key() -> str | None:
    key = os.environ.get("NVD_API_KEY", "").strip()
    return key or None


def fetch_nvd(cve_id: str, api_key: str | None) -> tuple[dict | None, bool]:
    """(record, answered). answered is False only when the lookup itself
    failed, so a transient error is never recorded as "NVD has nothing".
    The primary NVD-authored CVSS score is preferred, newest version first.
    """
    headers = {"apiKey": api_key} if api_key else {}
    try:
        data = get_json(f"{NVD_URL}?cveId={urllib.parse.quote(cve_id)}", headers)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, True
        return None, False
    except Exception:
        return None, False

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None, True
    cve = vulns[0].get("cve", {})
    metrics = cve.get("metrics", {})

    chosen = None
    for family in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(family) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss = primary.get("cvssData", {})
        if cvss.get("baseScore") is None:
            continue
        chosen = {
            "base_score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity") or primary.get("baseSeverity"),
            "version": cvss.get("version"),
            "vector": cvss.get("vectorString"),
        }
        break

    cwes = sorted({
        d.get("value") for w in cve.get("weaknesses", []) for d in w.get("description", [])
        if str(d.get("value", "")).startswith("CWE-")
    })
    record = {
        "base_score": (chosen or {}).get("base_score"),
        "severity": (chosen or {}).get("severity"),
        "version": (chosen or {}).get("version"),
        "vector": (chosen or {}).get("vector"),
        "cwes": cwes,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
    }
    return record, True


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """EPSS for a batch of CVEs. A CVE missing from the response has no score
    (very new or rejected), which is an answer."""
    out: dict[str, dict] = {}
    for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[i:i + EPSS_BATCH_SIZE]
        try:
            data = get_json(f"{EPSS_URL}?cve={','.join(batch)}")
        except Exception:
            continue  # the next run retries this batch
        for row in data.get("data", []):
            try:
                out[row["cve"]] = {
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                    "date": row.get("date"),
                }
            except (KeyError, TypeError, ValueError):
                continue
        time.sleep(0.3)
    return out


KEV_CACHE_S = 600
_kev_cache: tuple[float, dict] | None = None


def fetch_kev_catalog() -> dict[str, dict] | None:
    """The whole KEV catalog keyed by CVE ID, or None if it can't be fetched.
    Kept for 10 minutes, so a check's ingest (kev.py) and refresh share one
    download."""
    global _kev_cache
    if _kev_cache and time.monotonic() - _kev_cache[0] < KEV_CACHE_S:
        return _kev_cache[1]
    try:
        data = get_json(KEV_URL)
    except Exception:
        return None
    catalog = {v["cveID"]: v for v in data.get("vulnerabilities", []) if v.get("cveID")}
    _kev_cache = (time.monotonic(), catalog)
    return catalog


# An EPSS score older than this shows a stale marker; the next run refreshes it.
EPSS_STALE_AFTER_DAYS = 2

# NVD lookups per post-ingest refresh: enough to score the CVEs that just
# arrived, not a backfill (that's an explicit `enrich --limit N`).
POST_INGEST_NVD_LIMIT = 40


def refresh_after_ingest(conn) -> dict:
    """The pass at the end of every check, so the dashboard's facts are
    re-verified, not just re-listed. EPSS and KEV are cheap and always run;
    NVD is bounded, newest arrivals and high ticket first."""
    # First, so newly found mentions are scored in this same pass.
    mentions = db.backfill_cve_mentions(conn, extract.extract_cves)
    stats = db.backfill_exploited_in_wild(conn, extract.exploitation_evidence)
    summary = enrich(conn, nvd_limit=POST_INGEST_NVD_LIMIT)
    summary["mentions_added"] = mentions["mentions_added"]
    summary["exploit_claims"] = stats["cve_reports"]
    summary["exploit_cves"] = stats["distinct_cves"]
    return summary


def enrich(conn, nvd_limit: int = NVD_DEFAULT_LIMIT, do_nvd: bool = True,
           do_epss: bool = True, do_kev: bool = True,
           records_limit: int | None = None, do_coverage: bool = True) -> dict:
    # cverecord imports this module for get_json, so its constant is read
    # here at call time, never at import time.
    if records_limit is None:
        records_limit = cverecord.POST_INGEST_LIMIT
    api_key = nvd_api_key()
    # A step that didn't run has no counts, only its name in "skipped", so
    # nothing downstream can read "turned off" as "ran and found nothing".
    summary = {
        "source": "CVE enrichment (CVE record + NVD + EPSS + KEV)",
        "nvd_key": bool(api_key),
        "skipped": [step for step, on in (("records", records_limit), ("coverage", do_coverage),
                                          ("epss", do_epss), ("kev", do_kev), ("nvd", do_nvd)) if not on],
    }

    # First: the record is fast and usually has the score NVD hasn't got to.
    if records_limit:
        summary.update(cverecord.refresh(conn, records_limit))

    # Nuclei, Metasploit and Sigma: three listings, re-read at most daily.
    if do_coverage:
        summary.update(coverage.refresh(conn))

    if do_epss:
        due = db.cves_needing_epss(conn, EPSS_RECHECK_HOURS)
        scores = fetch_epss(due)
        db.record_epss_scores(conn, scores)
        summary["epss_updated"] = len(scores)

    if do_kev:
        catalog = fetch_kev_catalog()
        if catalog is not None:
            summary["kev_listed"] = db.record_kev_membership(conn, catalog)
        else:
            summary["kev_failed"] = True

    if do_nvd:
        summary.update(nvd_checked=0, nvd_scored=0, nvd_failed=0)
        delay = NVD_DELAY_WITH_KEY_S if api_key else NVD_DELAY_NO_KEY_S
        for cve_id in db.cves_needing_nvd(conn, NVD_RECHECK_DAYS, nvd_limit):
            record, answered = fetch_nvd(cve_id, api_key)
            if not answered:
                summary["nvd_failed"] += 1
            else:
                db.record_nvd_score(conn, cve_id, record)
                summary["nvd_checked"] += 1
                if record and record.get("base_score") is not None:
                    summary["nvd_scored"] += 1
            time.sleep(delay)

    # Last, so it scores on everything above: sets every priority and high_ticket.
    summary.update(priority.recompute(conn))
    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    return summary
