"""CISA KEV (Known Exploited Vulnerabilities) ingestion.

The feed is the whole catalog every time, so only entries added in the last
KEV_LOOKBACK_DAYS become articles; the CVE ID is the guid, so later runs skip
what's stored. KEV entries carry no CVSS score, but being listed is itself
the signal, so every one is high ticket.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import db
import enrich
import extract

KEV_LOOKBACK_DAYS = 30


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_date_added(raw: str) -> str:
    """KEV's YYYY-MM-DD as a UTC-midnight timestamp, so it sorts with the
    other sources' full timestamps."""
    return datetime.combine(
        date.fromisoformat(raw), datetime.min.time(), tzinfo=timezone.utc
    ).isoformat()


def _entry_link(entry: dict) -> str:
    """KEV's `notes` is often several URLs joined with ';'. Take the first if
    it's a link, else the NVD page."""
    notes = entry.get("notes") or ""
    first_segment = notes.split(";")[0].strip()
    if first_segment.startswith("http"):
        return first_segment
    return f"https://nvd.nist.gov/vuln/detail/{entry['cveID']}"


def ingest_kev(conn) -> dict:
    source_id = db.upsert_source(conn, "CISA KEV", enrich.KEV_URL)
    cutoff = date.today() - timedelta(days=KEV_LOOKBACK_DAYS)

    summary = {"source": "CISA KEV", "seen": 0, "new": 0, "high_ticket": 0, "skipped_304": False}

    catalog = enrich.fetch_kev_catalog()
    if catalog is None:
        summary["error"] = "KEV catalog fetch failed"
        return summary

    watchlist, tags, campaigns = extract.load_filters()

    for entry in catalog.values():
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
        entity_matches = extract.match_named(text_for_matching, tags)
        campaign_matches = extract.match_named(text_for_matching, campaigns)

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
