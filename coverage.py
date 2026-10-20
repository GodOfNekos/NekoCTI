# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What already exists for a captured CVE, beyond a PoC repo:

  Nuclei      -- a ProjectDiscovery scanner template: anyone can scan for it
                 at scale, and so can Neko against their own estate.
  Metasploit  -- an exploit module: a weaponised, point-and-click exploit.
  Sigma       -- a SigmaHQ detection rule: something to hunt or alert with.

Each comes from one listing (two GitHub repository trees and Metasploit's
own module index), refreshed at most daily, so a check costs three requests.
NekoCTI stores links to the template, module or rule, never their content.

Exploit maturity is the ladder CVSS-BT uses (github.com/t0sche/cvss-bt):
ATTACKED (KEV or reported exploitation) over FUNCTIONAL (a Metasploit
exploit module or a Nuclei template) over POC (a public repo, or coverage
describing one) over UNPROVEN.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import db
import enrich

SOURCES = {
    "nuclei": ("https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1",
               "https://github.com/projectdiscovery/nuclei-templates/blob/main/"),
    "sigma": ("https://api.github.com/repos/SigmaHQ/sigma/git/trees/master?recursive=1",
              "https://github.com/SigmaHQ/sigma/blob/master/"),
}
METASPLOIT_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
METASPLOIT_LINK = "https://github.com/rapid7/metasploit-framework/blob/master"

REFRESH_AFTER_HOURS = 20       # the listings change daily at most
LISTING_TIMEOUT_S = 60         # each is several MB

# ponytail: Sigma and Nuclei are matched on the CVE ID in the file path.
# SigmaHQ names CVE rules that way, but a rule that only carries a
# `cve.YYYY-NNNN` tag inside the file is missed; reading every rule would
# mean thousands of fetches. Revisit if a missed rule turns up.
_PATH_CVE_RE = re.compile(r"CVE[-_](\d{4})[-_](\d{4,7})", re.IGNORECASE)

MATURITY_ORDER = ("ATTACKED", "FUNCTIONAL", "POC", "UNPROVEN")


def _from_tree(url: str, link_base: str) -> dict[str, list[tuple[str, str]]] | None:
    """CVE ID to [(path, link)] from a repository tree, or None if the listing
    failed or came back truncated."""
    try:
        data = enrich.get_json(url, enrich.github_headers(), LISTING_TIMEOUT_S)
    except Exception:
        return None
    if data.get("truncated") or "tree" not in data:
        return None
    out: dict[str, list[tuple[str, str]]] = {}
    for entry in data["tree"]:
        path = entry.get("path", "")
        # SigmaHQ keeps retired rules under deprecated/.
        if entry.get("type") != "blob" or not path.endswith((".yaml", ".yml")) or path.startswith("deprecated/"):
            continue
        for year, seq in set(_PATH_CVE_RE.findall(path)):
            out.setdefault(f"CVE-{year}-{seq}", []).append((path, link_base + path))
    return out


def _from_metasploit() -> dict[str, list[tuple[str, str]]] | None:
    """CVE ID to [(module name, link)] for exploit modules. Auxiliary modules
    are mostly scanners, so they don't count as a working exploit."""
    try:
        data = enrich.get_json(METASPLOIT_URL, timeout=LISTING_TIMEOUT_S)
    except Exception:
        return None
    out: dict[str, list[tuple[str, str]]] = {}
    for module in data.values():
        if module.get("type") != "exploit":
            continue
        for ref in module.get("references") or []:
            ref = str(ref).upper()
            if ref.startswith("CVE-"):
                out.setdefault(ref, []).append((module.get("fullname", ""),
                                                METASPLOIT_LINK + module.get("path", "")))
    return out


def refresh(conn, force: bool = False) -> dict:
    """Re-read the three listings when the stored ones are older than
    REFRESH_AFTER_HOURS. A listing that fails keeps its previous rows."""
    summary = {"coverage_refreshed": [], "coverage_failed": []}
    last = db.get_coverage_refreshed_at(conn)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=REFRESH_AFTER_HOURS)
    captured = db.get_all_captured_cve_ids(conn)
    fetchers = {kind: (lambda u=url, b=base: _from_tree(u, b)) for kind, (url, base) in SOURCES.items()}
    fetchers["metasploit"] = _from_metasploit
    for kind, fetch in fetchers.items():
        when = last.get(kind)
        if not force and when and datetime.fromisoformat(when) >= cutoff:
            continue
        listing = fetch()
        if listing is None:
            summary["coverage_failed"].append(kind)
            continue
        rows = [(cve, ref, link) for cve, items in listing.items() if cve in captured for ref, link in items]
        db.replace_coverage(conn, kind, rows)
        summary["coverage_refreshed"].append(kind)
    return summary


def exploit_maturity(kev: bool, reported: bool, kinds: set[str], poc_repo: bool, poc_mentioned: bool) -> str:
    if kev or reported:
        return "ATTACKED"
    if kinds & {"metasploit", "nuclei"}:
        return "FUNCTIONAL"
    if poc_repo or poc_mentioned:
        return "POC"
    return "UNPROVEN"
