"""Public PoC availability for captured CVEs, from nomi-sec/PoC-in-GitHub:
one JSON file per CVE listing the GitHub repos that claim to be a PoC. A
lookup keyed on CVE ID, so it enriches captured CVEs rather than ingesting.
"""

from __future__ import annotations

import re
import time
import urllib.error

import db
import enrich

BASE_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
RECHECK_AFTER_HOURS = 24
REQUEST_TIMEOUT_S = 10

# Pacing against a third-party CDN: a run can make hundreds of requests.
REQUEST_DELAY_S = 0.2

_CVE_YEAR_RE = re.compile(r"^CVE-(\d{4})-")


def fetch_pocs_for_cve(cve_id: str) -> list[dict] | None:
    """The PoC repos for one CVE, [] if none exist (a 404), or None on any
    other failure, so a network error isn't recorded as "checked, none"."""
    m = _CVE_YEAR_RE.match(cve_id)
    if not m:
        return None
    year = m.group(1)
    url = f"{BASE_URL}/{year}/{cve_id}.json"
    try:
        return enrich.get_json(url, timeout=REQUEST_TIMEOUT_S)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        return None
    except Exception:
        return None


def check_pocs(conn) -> dict:
    cve_ids = db.cves_needing_poc_check(conn, RECHECK_AFTER_HOURS)
    # "new" counts repos found, not articles; "kind" keeps it out of the
    # dashboard's "+N NEW" article total.
    summary = {"source": "PoC-in-GitHub enrichment", "kind": "enrichment", "seen": len(cve_ids), "new": 0,
               "high_ticket": 0, "skipped_304": False}

    for cve_id in cve_ids:
        pocs = fetch_pocs_for_cve(cve_id)
        if pocs is None:
            continue  # fetch failure: left unchecked, retried next run
        db.replace_cve_pocs(conn, cve_id, pocs)
        if pocs:
            summary["new"] += len(pocs)
        time.sleep(REQUEST_DELAY_S)

    return summary
