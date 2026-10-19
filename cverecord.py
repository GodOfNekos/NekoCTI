# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The CVE record itself, from the CVE Program's cvelistV5 repository: the
CNA's own CVSS score (else CISA's, from its ADP container), CISA's SSVC
decision points, CWE, and every affected vendor and product. Keyed on CVE ID
like pocs.py.

The CNA publishes here first; NVD's analysis lags, often by weeks for new
CVEs. NVD stays the authoritative score when it has one (enrich.py), and the
dashboard says which source it is showing.

The affected list is also the CVE-to-vendor link. An article's vendor tags
describe the article; a roundup naming 60 CVEs and "Microsoft" once doesn't
make all 60 Microsoft's.
"""

from __future__ import annotations

import re
import urllib.error
from concurrent.futures import ThreadPoolExecutor

import db
import enrich
import extract

BASE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
REQUEST_TIMEOUT_S = 15
# A fetch is network-bound (0.47s average, measured 19 October 2026), so a
# few run at once; writes stay on the calling thread. A CDN, not a
# rate-limited API, but kept small to stay polite.
FETCH_WORKERS = 4

# A record is read again only while young and still missing a score or SSVC.
RECHECK_DAYS = 7
YOUNG_DAYS = 90

# Per check: enough for the CVEs that just arrived. A backfill is an explicit
# `enrich --records N`.
POST_INGEST_LIMIT = 300

# Newest CVSS version first, as in enrich.fetch_nvd.
_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$")
_NOT_A_NAME = {"", "n/a", "na", "unknown", "unspecified"}


def record_url(cve_id: str) -> str | None:
    """cvelistV5 files each record under its year and thousands block:
    CVE-2026-111472 is cves/2026/111xxx/CVE-2026-111472.json."""
    m = _CVE_ID_RE.match(cve_id)
    if not m:
        return None
    year, seq = m.group(1), int(m.group(2))
    return f"{BASE_URL}/{year}/{seq // 1000}xxx/{cve_id}.json"


def fetch_record(cve_id: str) -> tuple[dict | None, bool]:
    """(record, answered), like enrich.fetch_nvd: answered is False only when
    the lookup itself failed, so a network error isn't recorded as "no
    record". A 404 is an answer: the ID is reserved or doesn't exist."""
    url = record_url(cve_id)
    if url is None:
        return None, True
    try:
        return enrich.get_json(url, timeout=REQUEST_TIMEOUT_S), True
    except urllib.error.HTTPError as e:
        return None, e.code == 404
    except Exception:
        return None, False


def _first_cvss(metrics: list[dict]) -> dict | None:
    for key in _CVSS_KEYS:
        for m in metrics or []:
            cvss = m.get(key)
            if cvss and cvss.get("baseScore") is not None:
                return cvss
    return None


def parse_record(rec: dict) -> dict:
    """The fields NekoCTI keeps from one CVE JSON 5 record."""
    meta = rec.get("cveMetadata") or {}
    containers = rec.get("containers") or {}
    cna = containers.get("cna") or {}
    adps = containers.get("adp") or []

    cvss, source = _first_cvss(cna.get("metrics")), "CNA"
    if cvss is None:
        for adp in adps:
            cvss = _first_cvss(adp.get("metrics"))
            if cvss is not None:
                source = (adp.get("providerMetadata") or {}).get("shortName") or "ADP"
                break

    ssvc: dict[str, str] = {}
    for adp in adps:
        for m in adp.get("metrics") or []:
            other = m.get("other") or {}
            if other.get("type") == "ssvc":
                for option in (other.get("content") or {}).get("options") or []:
                    ssvc.update({k.lower(): str(v).lower() for k, v in option.items()})

    cwes = sorted({
        d.get("cweId") for container in (cna, *adps)
        for p in container.get("problemTypes") or [] for d in p.get("descriptions") or []
        if str(d.get("cweId", "")).startswith("CWE-")
    })

    affected = []
    for a in cna.get("affected") or []:
        vendor = (a.get("vendor") or "").strip()
        product = (a.get("product") or "").strip()
        vendor = "" if vendor.lower() in _NOT_A_NAME else vendor
        product = "" if product.lower() in _NOT_A_NAME else product
        if (vendor or product) and (vendor, product) not in affected:
            affected.append((vendor, product))

    return {
        "state": meta.get("state"),
        "published": meta.get("datePublished"),
        "base_score": (cvss or {}).get("baseScore"),
        "severity": (cvss or {}).get("baseSeverity"),
        "version": (cvss or {}).get("version"),
        "vector": (cvss or {}).get("vectorString"),
        "score_source": source if cvss else None,
        "ssvc_exploitation": ssvc.get("exploitation"),
        "ssvc_automatable": ssvc.get("automatable"),
        "ssvc_technical_impact": ssvc.get("technical impact"),
        "cwes": cwes,
        "affected": affected,
    }


def refresh(conn, limit: int = POST_INGEST_LIMIT) -> dict:
    summary = {"records_checked": 0, "records_scored": 0, "records_failed": 0}
    cve_ids = db.cves_needing_record(conn, RECHECK_DAYS, YOUNG_DAYS, limit)
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        # map() keeps order and hands back each result as it lands.
        for cve_id, (rec, answered) in zip(cve_ids, pool.map(fetch_record, cve_ids)):
            if not answered:
                summary["records_failed"] += 1
                continue  # left unchecked, retried next run
            parsed = parse_record(rec) if rec else None
            db.record_cve_record(conn, cve_id, parsed)
            summary["records_checked"] += 1
            if parsed and parsed["base_score"] is not None:
                summary["records_scored"] += 1
    return summary


def watchlist_terms(conn, cve_ids: list[str], watchlist: dict[str, list[str]]) -> dict[str, list[str]]:
    """Watchlist terms per CVE, from the record's affected vendors and
    products. A CVE whose record lists none falls back to the titles of
    articles naming 5 or fewer CVEs, never to a roundup or a body's
    passing mentions."""
    affected = db.get_cve_affected(conn, cve_ids)
    missing = [c for c in cve_ids if not affected.get(c)]
    fallback = db.get_small_article_titles(conn, missing)
    out: dict[str, list[str]] = {}
    for cve_id in cve_ids:
        pairs = affected.get(cve_id)
        if pairs:
            text = " ; ".join(f"{v} {p}" for v, p in pairs)
        else:
            text = " ; ".join(fallback.get(cve_id, ()))
        terms = sorted({term for _, term in extract.match_vendors(text, watchlist)})
        if terms:
            out[cve_id] = terms
    return out
