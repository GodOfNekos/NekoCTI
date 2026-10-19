# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Public PoC availability for captured CVEs, from nomi-sec/PoC-in-GitHub:
one JSON file per CVE listing the GitHub repos that claim to be a PoC. A
lookup keyed on CVE ID, so it enriches captured CVEs rather than ingesting.

One request lists every file in the repository with its git blob hash, so a
check reads only the files that are new or changed since last time. A CVE
with no file has no public PoC, without fetching anything. Re-reading every
captured CVE's file instead took over 30 minutes a check by 28 September
2026, and grows with the archive.
"""

from __future__ import annotations

import re
import time
import urllib.error

import db
import enrich

BASE_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
TREE_URL = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/master?recursive=1"
REQUEST_TIMEOUT_S = 10
TREE_TIMEOUT_S = 60            # the listing is about 3 MB

# Pacing against a third-party CDN for the files that did change.
REQUEST_DELAY_S = 0.2

_CVE_YEAR_RE = re.compile(r"^CVE-(\d{4})-")
_TREE_PATH_RE = re.compile(r"^\d{4}/(CVE-\d{4}-\d{4,7})\.json$")


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


def fetch_poc_index() -> dict[str, str] | None:
    """CVE ID to blob hash for every PoC file in the repository, or None when
    the listing can't be trusted: a failed request, or GitHub truncating it
    (it does past 100,000 entries; 11,241 files on 19 October 2026)."""
    try:
        data = enrich.get_json(TREE_URL, enrich.github_headers(), TREE_TIMEOUT_S)
    except Exception:
        return None
    if data.get("truncated") or "tree" not in data:
        return None
    index = {}
    for entry in data["tree"]:
        m = _TREE_PATH_RE.match(entry.get("path", ""))
        if m and entry.get("sha"):
            index[m.group(1)] = entry["sha"]
    return index


def check_pocs(conn) -> dict:
    # "new" counts repos found, not articles; "kind" keeps it out of the
    # dashboard's "+N NEW" article total.
    summary = {"source": "PoC-in-GitHub enrichment", "kind": "enrichment", "seen": 0, "new": 0,
               "high_ticket": 0, "skipped_304": False, "files_read": 0, "unchanged": 0}

    index = fetch_poc_index()
    stored = db.get_poc_blob_shas(conn)
    if index is None:
        # Without the listing, only never-checked CVEs are read file by file.
        # Never a sweep of the whole archive, which is what made checks slow.
        summary["index_failed"] = True
        todo = {cve_id: None for cve_id in db.all_cve_ids(conn) if cve_id not in stored}
    else:
        todo = {}
        for cve_id in db.all_cve_ids(conn):
            sha = index.get(cve_id, "")          # "" is "no PoC file"
            if cve_id in stored and stored[cve_id] == sha:
                summary["unchanged"] += 1
            else:
                todo[cve_id] = sha

    for cve_id, sha in todo.items():
        summary["seen"] += 1
        if sha == "":
            db.replace_cve_pocs(conn, cve_id, [], blob_sha="")   # no file: nothing to fetch
            continue
        pocs = fetch_pocs_for_cve(cve_id)
        if pocs is None:
            continue  # fetch failure: left as it was, retried next run
        db.replace_cve_pocs(conn, cve_id, pocs, blob_sha=sha)
        summary["files_read"] += 1
        summary["new"] += len(pocs)
        time.sleep(REQUEST_DELAY_S)

    return summary
