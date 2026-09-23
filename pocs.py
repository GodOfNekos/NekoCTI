"""Real public PoC-exploit availability, per real CVE NekoCTI has already
captured.

An enrichment lookup against `nomi-sec/PoC-in-GitHub` (checked real, 16
September 2026: 8k+ stars, pushed within the last few hours at check
time, so genuinely active, not abandoned) -- one real JSON file per CVE
ID, organized by year, containing the real GitHub repos claiming to be a
PoC for that CVE (name, url, description, star count, dates). This is a
lookup table keyed on CVE ID, the same shape as NVD/EPSS were already
scoped as (see the vault note's own source-research pass) -- there's no
"new PoC article" to ingest, only "does a public PoC exist for a CVE
we've already seen", so this enriches already-captured CVEs rather than
running as its own standalone source with an ingestion tab of its own.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

import db

BASE_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
RECHECK_AFTER_HOURS = 24
REQUEST_TIMEOUT_S = 10

# Polite pacing against a real third-party raw-content CDN -- this can mean
# hundreds of real per-CVE requests in one run, so this isn't optional.
REQUEST_DELAY_S = 0.2

_CVE_YEAR_RE = re.compile(r"^CVE-(\d{4})-")


def fetch_pocs_for_cve(cve_id: str) -> list[dict] | None:
    """Real PoC repos for one CVE, or [] if genuinely none exist (a real
    404 from the lookup), or None on an unrelated fetch failure -- the
    None case is deliberately NOT treated the same as a real zero-result,
    so a network hiccup doesn't get recorded as "checked, no PoCs" and
    silently skip a real future recheck."""
    m = _CVE_YEAR_RE.match(cve_id)
    if not m:
        return None
    year = m.group(1)
    url = f"{BASE_URL}/{year}/{cve_id}.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NekoCTI"})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_S) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        return None
    except Exception:
        return None


def check_pocs(conn) -> dict:
    cve_ids = db.cves_needing_poc_check(conn, RECHECK_AFTER_HOURS)
    # "new" here counts PoC repos found, not articles; "kind" marks this entry
    # as enrichment so the dashboard's "+N NEW" total leaves it out (it read
    # +3,507 NEW for a check that brought in 223 articles, 23 September 2026).
    summary = {"source": "PoC-in-GitHub enrichment", "kind": "enrichment", "seen": len(cve_ids), "new": 0,
               "high_ticket": 0, "skipped_304": False}

    for cve_id in cve_ids:
        pocs = fetch_pocs_for_cve(cve_id)
        if pocs is None:
            continue  # real fetch failure -- leave unchecked, retried next run
        db.replace_cve_pocs(conn, cve_id, pocs)
        if pocs:
            summary["new"] += len(pocs)
        time.sleep(REQUEST_DELAY_S)

    return summary
