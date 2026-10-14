# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GitHub Security Advisories ingestion.

A JSON API, not RSS, so it has its own module like kev.py. It supports a
published-date filter and sorting, so each run fetches one page of recent
advisories. Unauthenticated limit is 60 requests an hour; GITHUB_TOKEN is
honoured if set (5,000 an hour). Package and ecosystem names are matched
against the watchlist alongside the text.
"""

from __future__ import annotations

import os
import re
from datetime import date, datetime, timedelta, timezone

import db
import enrich
import extract

GHSA_URL = "https://api.github.com/advisories"
GHSA_LOOKBACK_DAYS = 30
PER_PAGE = 100
REQUEST_TIMEOUT_S = 20

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def real_title(summary: str | None, description: str | None, fallback: str) -> str:
    """Unreviewed advisories often have a `summary` cut off with '...'; use
    the description's first sentence instead."""
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
    """One page of advisories published after `since`, newest first. No
    pagination, to stay well under the unauthenticated rate limit."""
    url = (
        f"{GHSA_URL}?published=%3E{since.isoformat()}"
        f"&per_page={PER_PAGE}&sort=published&direction=desc"
    )
    return enrich.get_json(url, _headers(), REQUEST_TIMEOUT_S)


def _normalize_timestamp(raw: str) -> str:
    """'Z' to '+00:00', matching every other stored timestamp."""
    return raw.replace("Z", "+00:00") if raw else raw


def _cvss_score(entry: dict) -> float | None:
    """CVSS v4, then v3, then the deprecated top-level field."""
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

    watchlist, tags, campaigns = extract.load_filters()

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
        entity_matches = extract.match_named(text_for_matching, tags)
        campaign_matches = extract.match_named(text_for_matching, campaigns)
        # The API gives the score directly, plus GitHub's reviewed severity.
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
