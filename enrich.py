"""Per-CVE enrichment: official severity, predicted exploitation, and
confirmed real-world exploitation, for CVEs NekoCTI has already captured.

Same shape as pocs.py: lookups keyed on CVE ID, not polled sources. There is
no "new severity article" to ingest, only "what is actually known about this
CVE". Three real lookups, each chosen because it answers a different question:

  NVD 2.0   -- the official CVSS base score, severity, vector and CWE. Most
               captured CVEs have no score at all otherwise: only the few
               whose article text happened to quote one (280 of 4,102 when
               this was built). Single-CVE queries, and rate-limited: 5
               requests per rolling 30s without an API key, 50 with one, so
               a run is always bounded by --limit and ordered by triage
               priority rather than database order.
  EPSS      -- FIRST.org's predicted probability that a CVE will be
               exploited in the next 30 days, plus its percentile against
               every scored CVE. Batched (one request covers many CVEs) and
               recomputed daily, so every captured CVE is refreshed.
  CISA KEV  -- membership of the Known Exploited Vulnerabilities catalog.
               This is confirmed exploitation in the wild, not a prediction,
               and it is the strongest signal of the three. kev.py already
               ingests recent KEV entries as articles; this marks the flag
               on any captured CVE, however old the entry.

The distinction matters when reading the dashboard: KEV means it is being
exploited, EPSS means it probably will be, a public PoC (pocs.py) means the
code to do it exists.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import db

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

REQUEST_TIMEOUT_S = 30
EPSS_BATCH_SIZE = 100          # the API takes a comma-separated list; 100 keeps the URL sane
EPSS_RECHECK_HOURS = 20        # EPSS is recomputed daily
NVD_RECHECK_DAYS = 7           # only matters for CVEs NVD has not finished analysing
NVD_DEFAULT_LIMIT = 200

# NVD's published limits: 5 requests per rolling 30s unkeyed, 50 with a key.
# The sleeps sit just inside those, because being throttled costs more time
# than pacing does.
NVD_DELAY_WITH_KEY_S = 0.7
NVD_DELAY_NO_KEY_S = 6.5

# An article is promoted to high ticket when a CVE it mentions is at or above
# this EPSS percentile. 0.95 is the top 5% most likely to be exploited.
HIGH_TICKET_EPSS_PERCENTILE = 0.95


def _get_json(url: str, headers: dict | None = None):
    req = urllib.request.Request(url, headers={"User-Agent": "NekoCTI", **(headers or {})})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_S) as resp:
        return json.loads(resp.read().decode("utf-8"))


def nvd_api_key() -> str | None:
    key = os.environ.get("NVD_API_KEY", "").strip()
    return key or None


def fetch_nvd(cve_id: str, api_key: str | None) -> tuple[dict | None, bool]:
    """Returns (record, answered). `answered` is False only when the lookup
    itself failed (network, throttling, a 503), so a transient error is never
    recorded as "NVD has nothing on this CVE" -- the same distinction pocs.py
    makes. A real empty result returns (None, True).

    NVD returns several metric families for one CVE (CVSS 4.0, 3.1, 3.0, and
    non-CVSS decision points). The primary NVD-authored CVSS score is
    preferred, then any other provider's, newest CVSS version first.
    """
    headers = {"apiKey": api_key} if api_key else {}
    try:
        data = _get_json(f"{NVD_URL}?cveId={urllib.parse.quote(cve_id)}", headers)
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
    """EPSS for a batch of CVEs. A CVE with no EPSS score simply isn't in the
    response (very new or rejected identifiers), which is a real answer."""
    out: dict[str, dict] = {}
    for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[i:i + EPSS_BATCH_SIZE]
        try:
            data = _get_json(f"{EPSS_URL}?cve={','.join(batch)}")
        except Exception:
            continue  # leave this batch unchecked; the next run retries it
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


def fetch_kev_catalog() -> dict[str, dict] | None:
    """The whole KEV catalog, keyed by CVE ID. One request covers every
    entry, so there is no reason to page or filter by date here -- kev.py's
    lookback window exists for article ingestion, not for this flag."""
    try:
        data = _get_json(KEV_URL)
    except Exception:
        return None
    return {v["cveID"]: v for v in data.get("vulnerabilities", []) if v.get("cveID")}


def enrich(conn, nvd_limit: int = NVD_DEFAULT_LIMIT, do_nvd: bool = True,
           do_epss: bool = True, do_kev: bool = True) -> dict:
    api_key = nvd_api_key()
    summary = {
        "source": "CVE enrichment (NVD + EPSS + KEV)",
        "epss_updated": 0, "kev_listed": 0, "nvd_checked": 0, "nvd_scored": 0,
        "nvd_failed": 0, "promoted_high_ticket": 0, "nvd_key": bool(api_key),
    }

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

    summary["promoted_high_ticket"] = db.refresh_high_ticket_from_scores(
        conn, HIGH_TICKET_EPSS_PERCENTILE)
    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    return summary
