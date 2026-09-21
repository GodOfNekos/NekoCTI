"""GitHub Security Advisories (GHSA) ingestion.

The real API was checked before writing this, 16 September 2026:
`https://api.github.com/advisories` returns structured JSON, not RSS, so
like CISA KEV it gets its own fetch/parse module rather than being forced
through feedparser. Confirmed working unauthenticated (HTTP 200), with a
real `published=>YYYY-MM-DD` filter and `sort=published&direction=desc`
supported directly by the API -- so this polls incrementally by date
rather than pulling the whole catalog every run the way KEV has to.

What makes this genuinely distinct from the RSS sources: advisories carry
real structured package/ecosystem data (`vulnerabilities[].package.{ecosystem,
name}`) that prose articles never have, so a future filter could weight or
surface advisories against ecosystems NekoCTI's watchlist actually cares
about (npm, pip, actions, etc.) -- not built yet, but the data is captured
now via vendor/entity matching against that field alongside the summary
and description text.

Unauthenticated rate limit is 60 requests/hour (real, confirmed via the
`X-RateLimit-Limit` response header) -- fine for this poll cadence (one
page, ~100 records, per run) but an optional `GITHUB_TOKEN` env var is
honored if set, since GitHub's documented authenticated rate is 5000/hour.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from datetime import date, datetime, timedelta, timezone

import db
import extract

GHSA_URL = "https://api.github.com/advisories"
GHSA_LOOKBACK_DAYS = 30
PER_PAGE = 100
REQUEST_TIMEOUT_S = 20

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def real_title(summary: str | None, description: str | None, fallback: str) -> str:
    """GHSA's own `summary` field is truncated mid-word with a literal '...'
    for many auto-imported ("unreviewed") advisories -- confirmed live, 16
    September 2026: a real entry's `summary` ended
    '...authorization bypass vulnerability in the GetFileContents API...'
    while its `description` held the real complete sentence
    ('...API endpoint that allows any authenticated user to read...').
    Falls back to the first real sentence of `description` instead of
    trusting a `summary` that ends in '...'."""
    summary = (summary or "").strip()
    if summary and not summary.endswith("..."):
        return summary
    description = (description or "").strip()
    if description:
        first = _SENTENCE_SPLIT_RE.split(description, maxsplit=1)[0].strip()
        if first:
            return first
    return summary or fallback


def _headers() -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "NekoCTI",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_advisories(since: date) -> list[dict]:
    """One page of real advisories published on/after `since`, newest
    first. A single page (up to PER_PAGE) is enough for a daily poll
    cadence -- deliberately not following pagination further, to stay well
    under the unauthenticated rate limit on every run."""
    url = (
        f"{GHSA_URL}?published=%3E{since.isoformat()}"
        f"&per_page={PER_PAGE}&sort=published&direction=desc"
    )
    req = urllib.request.Request(url, headers=_headers())
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_S) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _normalize_timestamp(raw: str) -> str:
    """GHSA's own timestamps are already real ISO 8601, just with a
    trailing 'Z' instead of the '+00:00' offset the rest of this codebase
    writes -- normalized here so string sort stays consistent everywhere."""
    return raw.replace("Z", "+00:00") if raw else raw


def _cvss_score(entry: dict) -> float | None:
    """Prefer the newer CVSS v4 score, then v3, then the deprecated
    top-level field -- whichever the real advisory actually populated."""
    severities = entry.get("cvss_severities") or {}
    for key in ("cvss_v4", "cvss_v3"):
        score = (severities.get(key) or {}).get("score")
        if score:
            return float(score)
    legacy = (entry.get("cvss") or {}).get("score")
    return float(legacy) if legacy else None


def ingest_ghsa(conn) -> dict:
    source_id = db.upsert_source(conn, "GitHub Security Advisories", GHSA_URL)
    cutoff = date.today() - timedelta(days=GHSA_LOOKBACK_DAYS)

    summary = {"source": "GitHub Security Advisories", "seen": 0, "new": 0,
               "high_ticket": 0, "skipped_304": False}

    try:
        advisories = fetch_advisories(cutoff)
    except Exception as e:
        summary["error"] = str(e)
        return summary

    watchlist = extract.load_watchlist()
    tags = extract.load_tags()
    campaigns = extract.load_campaigns()

    for entry in advisories:
        summary["seen"] += 1

        guid = entry.get("ghsa_id")
        link = entry.get("html_url") or entry.get("url") or ""
        if not guid or not link:
            continue

        nlink = db.normalize_link(link)
        if db.article_exists(conn, nlink, guid):
            continue

        title = real_title(entry.get("summary"), entry.get("description"), guid)
        body = entry.get("description") or ""
        severity = entry.get("severity") or ""
        cve_id = entry.get("cve_id")
        score = _cvss_score(entry)

        packages = entry.get("vulnerabilities") or []
        package_text = " ".join(
            f"{p.get('package', {}).get('ecosystem', '')} {p.get('package', {}).get('name', '')}"
            for p in packages
        )
        text_for_matching = " ".join(filter(None, [title, body, package_text]))

        vendor_matches = extract.match_vendors(text_for_matching, watchlist)
        entity_matches = extract.match_entities(text_for_matching, tags)
        campaign_matches = extract.match_campaigns(text_for_matching, campaigns)
        # KEV-style: for RSS sources "high ticket" comes from a CVSS score
        # found in free text; here the API hands the score directly, plus
        # GitHub's own reviewed severity rating as a second real signal.
        high_ticket = (score is not None and score >= extract.HIGH_TICKET_CVSS_THRESHOLD) \
            or severity.lower() in ("critical", "high")
        breach = extract.is_breach(title, body)
        poc_mentioned = extract.mentions_poc(title, body)

        article_id = db.insert_article(
            conn,
            source_id=source_id,
            guid=guid,
            link=link,
            title=title,
            published_at=_normalize_timestamp(entry.get("published_at")),
            fetched_at=datetime.now(timezone.utc).isoformat(),
            description=title,
            full_text=body or None,
            high_ticket=high_ticket,
            is_breach=breach,
            mentions_poc=poc_mentioned,
        )
        if article_id is None:
            continue

        if cve_id:
            db.insert_cve_mentions(conn, article_id, [(cve_id, score)])
        if vendor_matches:
            db.insert_vendor_matches(conn, article_id, vendor_matches)
        if entity_matches:
            db.insert_entity_matches(conn, article_id, entity_matches)
        if campaign_matches:
            db.insert_campaign_matches(conn, article_id, campaign_matches)

        summary["new"] += 1
        if high_ticket:
            summary["high_ticket"] += 1

    db.update_source_polled(conn, source_id, None, None, datetime.now(timezone.utc).isoformat())
    return summary
