"""CISA KEV (Known Exploited Vulnerabilities) ingestion.

The real feed was checked before writing this, 16 September 2026:
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
returns a flat JSON object with a `vulnerabilities` array holding the FULL
historical catalog (1710 entries at check time), not an incremental delta
-- CISA republishes the whole thing on every release, no UA header
required. So ingestion filters to entries added within KEV_LOOKBACK_DAYS
before ever touching the database, rather than backfilling years of
history that isn't operationally relevant to ongoing monitoring. The
existing link+guid dedup (keyed on the CVE ID itself here, a much more
natural per-entry identifier than anything RSS offers) skips entries
already stored on every later run, so a real new addition still gets
caught even outside the lookback window on the run right after it's added.

No CVSS score is given directly by KEV entries. Being listed in the
catalog at all is itself the high-signal fact -- a real, confirmed
actively-exploited vulnerability with a CISA-set remediation due date --
so every KEV entry is marked high_ticket unconditionally, unlike the
CVSS-threshold logic used for regular RSS articles.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import date, datetime, timedelta, timezone

import db
import extract

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_LOOKBACK_DAYS = 30
REQUEST_TIMEOUT_S = 20


def fetch_kev_catalog() -> dict:
    with urllib.request.urlopen(KEV_URL, timeout=REQUEST_TIMEOUT_S) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_date_added(raw: str) -> str:
    """KEV's `dateAdded` is a plain `YYYY-MM-DD` string with no time
    component. Expanded to a full UTC-midnight ISO timestamp so it sorts
    consistently against THN's full datetime `published_at` values -- a
    bare date string is a valid prefix-match "less than" a same-day
    datetime string in Python's own comparison, which is harmless day to
    day but inconsistent with every other source, so it's normalized here
    instead of relied on."""
    return datetime.combine(
        date.fromisoformat(raw), datetime.min.time(), tzinfo=timezone.utc
    ).isoformat()


def _entry_link(entry: dict) -> str:
    """KEV's own `notes` field is often several URLs joined with `;`
    (confirmed against the real feed, 16 September 2026 - e.g. a vendor
    advisory, two CISA directive links, then an NVD link, all in one
    string), sometimes with a "Label: " prefix on later entries. Take the
    first semicolon-separated segment; fall back to a constructed NVD URL
    if notes is empty or doesn't start with a real link."""
    notes = entry.get("notes") or ""
    first_segment = notes.split(";")[0].strip()
    if first_segment.startswith("http"):
        return first_segment
    return f"https://nvd.nist.gov/vuln/detail/{entry['cveID']}"


def ingest_kev(conn) -> dict:
    source_id = db.upsert_source(conn, "CISA KEV", KEV_URL)
    cutoff = date.today() - timedelta(days=KEV_LOOKBACK_DAYS)

    summary = {"source": "CISA KEV", "seen": 0, "new": 0, "high_ticket": 0, "skipped_304": False}

    try:
        catalog = fetch_kev_catalog()
    except Exception as e:
        summary["error"] = str(e)
        return summary

    watchlist = extract.load_watchlist()
    tags = extract.load_tags()
    campaigns = extract.load_campaigns()

    for entry in catalog.get("vulnerabilities", []):
        try:
            added = date.fromisoformat(entry["dateAdded"])
        except (KeyError, ValueError):
            continue
        if added < cutoff:
            continue

        summary["seen"] += 1

        link = _entry_link(entry)
        guid = entry["cveID"]
        nlink = db.normalize_link(link)
        if db.article_exists(conn, nlink, guid):
            continue

        title = entry.get("vulnerabilityName") or f"{entry.get('vendorProject', '')} - {guid}"
        description = " ".join(filter(None, [
            entry.get("shortDescription"),
            entry.get("requiredAction"),
        ]))
        text_for_matching = " ".join(filter(None, [
            entry.get("vendorProject"),
            entry.get("product"),
            title,
            description,
        ]))

        vendor_matches = extract.match_vendors(text_for_matching, watchlist)
        entity_matches = extract.match_entities(text_for_matching, tags)
        campaign_matches = extract.match_campaigns(text_for_matching, campaigns)

        article_id = db.insert_article(
            conn,
            source_id=source_id,
            guid=guid,
            link=link,
            title=title,
            published_at=_normalize_date_added(entry["dateAdded"]),
            fetched_at=_now_iso(),
            description=description,
            full_text=None,
            high_ticket=True,
        )
        if article_id is None:
            continue

        db.insert_cve_mentions(conn, article_id, [(guid, None)])
        if vendor_matches:
            db.insert_vendor_matches(conn, article_id, vendor_matches)
        if entity_matches:
            db.insert_entity_matches(conn, article_id, entity_matches)
        if campaign_matches:
            db.insert_campaign_matches(conn, article_id, campaign_matches)

        summary["new"] += 1
        summary["high_ticket"] += 1

    db.update_source_polled(conn, source_id, None, None, _now_iso())
    return summary
