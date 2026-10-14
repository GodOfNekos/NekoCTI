# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RSS polling and full-article fetching.

Feed descriptions are often short teasers, so each item's full text comes
from the feed's own content field when it is long enough, else from fetching
the article page with Trafilatura. Conditional fetching (etag/last-modified)
skips unchanged feeds.
"""

from __future__ import annotations

import calendar
import ipaddress
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import feedparser
import trafilatura

import db
import extract
import ghsa
import kev
import pocs

# Each blog's own feed, found and test-fetched on 16 September 2026 from
# muchdogesec/awesome_threat_intel_blogs (134 of 191 had a working feed).
# GitHub Security Lab uses its tag feed, not github.blog's site-wide one.
SOURCES = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "DoublePulsar (Kevin Beaumont)": "https://doublepulsar.com/feed",
    "Troy Hunt": "https://www.troyhunt.com/rss/",
    "BushidoToken Threat Intel": "https://blog.bushidotoken.net/feeds/posts/default",
    "SecurityBreak": "https://blog.securitybreak.io/feed",
    "Tal Be'ery": "https://medium.com/@TalBeerySec/feed",
    "bellingcat": "https://www.bellingcat.com/feed",
    "deepdarkCTI": "https://deepdarkcti.com/feed/",
    "Citizen Lab": "https://citizenlab.ca/feed",
    "Ctrl-Alt-Int3l": "https://ctrlaltintel.com/feed.xml",
    "Detect FYI": "https://detect.fyi/feed",
    "JPCERT": "https://blogs.jpcert.or.jp/en/atom.xml",
    "CERT Polska": "https://cert.pl/en/atom.xml",
    "Cisco Talos": "https://blog.talosintelligence.com/rss/",
    "Google Project Zero": "https://projectzero.google/feed.xml",
    "Microsoft Security Blog": "https://www.microsoft.com/en-us/security/blog/feed/",
    "SentinelOne": "https://www.sentinelone.com/blog/feed",
    "Recorded Future": "https://www.recordedfuture.com/feed",
    "SecureList by Kaspersky": "https://securelist.com/feed/",
    "Check Point Research": "https://research.checkpoint.com/feed",
    "Malwarebytes Labs": "https://www.malwarebytes.com/blog/feed",
    "Zero Day Initiative": "https://www.thezdi.com/blog?format=rss",
    "Cybereason": "https://www.cybereason.com/blog/rss.xml",
    "Tenable": "https://feeds.feedburner.com/tenable/qaXL",
    "VirusTotal Blog": "https://blog.virustotal.com/feeds/posts/default",
    "GitHub Security Lab": "https://github.blog/tag/github-security-lab/feed/",
    "Qualys Blog": "https://blog.qualys.com/feed",
    "NVISO Labs": "https://blog.nviso.eu/feed/",
    "EclecticIQ": "https://blog.eclecticiq.com/rss.xml",
    "Ars Technica Security": "https://arstechnica.com/tag/security/feed/",
    "CyberScoop": "https://cyberscoop.com/feed/",
}

FETCH_TIMEOUT_S = 20

# Below this length a feed's content field is another teaser: fetch the page.
MIN_FEED_CONTENT_CHARS = 800

# Inline images from the article, captured broadly and shown in the reader.
# Capped so one image-heavy page can't flood it.
MAX_IMAGES_PER_ARTICLE = 6
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_published(entry) -> str | None:
    """A sortable UTC timestamp. feedparser's parsed struct is already UTC;
    the raw string (then None) is the fallback when it couldn't parse one."""
    struct = entry.get("published_parsed") or entry.get("updated_parsed")
    if struct:
        dt = datetime.fromtimestamp(calendar.timegm(struct), tz=timezone.utc)
        return dt.isoformat()
    return entry.get("published") or entry.get("updated")


def _images_from_html(html: str) -> list[str]:
    """Inline content images, via Trafilatura's include_images extraction
    (its Markdown output just carries the URLs)."""
    try:
        md = trafilatura.extract(html, include_images=True, output_format="markdown")
    except Exception:
        return []
    if not md:
        return []
    seen: list[str] = []
    for url in _MD_IMAGE_RE.findall(md):
        if url not in seen:
            seen.append(url)
    return seen[:MAX_IMAGES_PER_ARTICLE]


def is_public_http_url(url: str, resolve=socket.getaddrinfo) -> bool:
    """An http(s) URL whose host resolves only to public addresses. Article
    links come from feeds, so without this a feed could point the fetcher at
    the host (host.docker.internal), the tailnet or the dashboard itself.
    ponytail: checks the first URL only; a redirect to a private address still
    gets through. Pin the resolved address per request if that ever matters."""
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        infos = resolve(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return False
    addrs = {ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos}
    return bool(addrs) and all(a.is_global for a in addrs)


def fetch_full_text(url: str) -> tuple[str | None, list[str]]:
    """Text and images from one page fetch; (None, []) on any failure, so one
    bad page never stops the run."""
    if not is_public_http_url(url):
        return None, []
    try:
        downloaded = trafilatura.fetch_url(url)
        if not downloaded:
            return None, []
        return trafilatura.extract(downloaded), _images_from_html(downloaded)
    except Exception:
        return None, []


def _extract_from_entry(entry, link: str) -> tuple[str | None, list[str]]:
    """The feed's own content field if it's long enough, else a page fetch."""
    feed_content = entry.get("content")
    if feed_content:
        html = feed_content[0].get("value", "")
        try:
            extracted = trafilatura.extract(html)
        except Exception:
            extracted = None
        if extracted and len(extracted) >= MIN_FEED_CONTENT_CHARS:
            return extracted, _images_from_html(html)
    return fetch_full_text(link) if link else (None, [])


def ingest_source(conn, name: str, feed_url: str) -> dict:
    """Poll one source, fetch and extract each new item, store it."""
    source_id = db.upsert_source(conn, name, feed_url)

    row = conn.execute(
        "SELECT etag, modified FROM sources WHERE id = ?", (source_id,)
    ).fetchone()
    prior_etag, prior_modified = row["etag"], row["modified"]

    parsed = feedparser.parse(feed_url, etag=prior_etag, modified=prior_modified)

    summary = {"source": name, "seen": 0, "new": 0, "high_ticket": 0, "skipped_304": False}

    if getattr(parsed, "status", None) == 304:
        summary["skipped_304"] = True
        db.update_source_polled(conn, source_id, prior_etag, prior_modified, _now_iso())
        return summary

    watchlist, tags, campaigns = extract.load_filters()

    for entry in parsed.entries:
        summary["seen"] += 1

        link = entry.get("link", "")
        guid = entry.get("id") or entry.get("guid")
        title = entry.get("title", "")
        description = entry.get("description", "") or entry.get("summary", "")
        published_at = normalize_published(entry)

        nlink = db.normalize_link(link)
        # Checked before paying for a full-article fetch (see article_exists).
        if db.article_exists(conn, nlink, guid):
            continue

        full_text, images = _extract_from_entry(entry, link)
        text_for_extraction = full_text or description

        cve_mentions = extract.extract_cves(text_for_extraction)
        vendor_matches = extract.match_vendors(text_for_extraction, watchlist)
        entity_matches = extract.match_named(text_for_extraction, tags)
        campaign_matches = extract.match_named(text_for_extraction, campaigns)
        high_ticket = extract.is_high_ticket(cve_mentions)
        breach = extract.is_breach(title, text_for_extraction)
        poc_mentioned = extract.mentions_poc(title, text_for_extraction)
        exploited = extract.exploited_in_wild(title, text_for_extraction)

        article_id = db.insert_article(
            conn,
            source_id=source_id,
            guid=guid,
            link=link,
            title=title,
            published_at=published_at,
            fetched_at=_now_iso(),
            description=description,
            full_text=full_text,
            high_ticket=high_ticket,
            is_breach=breach,
            mentions_poc=poc_mentioned,
            exploited_in_wild=exploited,
        )
        if article_id is None:
            continue   # the defensive backstop behind the pre-check

        if cve_mentions:
            db.insert_cve_mentions(conn, article_id, cve_mentions)
        if vendor_matches:
            db.insert_vendor_matches(conn, article_id, vendor_matches)
        if entity_matches:
            db.insert_entity_matches(conn, article_id, entity_matches)
        if campaign_matches:
            db.insert_campaign_matches(conn, article_id, campaign_matches)
        if images:
            db.insert_article_images(conn, article_id, images)

        summary["new"] += 1
        if high_ticket:
            summary["high_ticket"] += 1

    new_etag = getattr(parsed, "etag", None)
    new_modified = getattr(parsed, "modified", None)
    db.update_source_polled(conn, source_id, new_etag, new_modified, _now_iso())

    return summary


def run_all() -> list[dict]:
    """Every RSS source, then CISA KEV and GitHub Security Advisories (JSON
    APIs with their own modules), then PoC availability for the CVEs found."""
    db.init_db()
    conn = db.connect()
    try:
        results = [ingest_source(conn, name, url) for name, url in SOURCES.items()]
        results.append(kev.ingest_kev(conn))
        results.append(ghsa.ingest_ghsa(conn))
        results.append(pocs.check_pocs(conn))
        return results
    finally:
        conn.close()


if __name__ == "__main__":
    started = time.monotonic()
    results = run_all()
    for r in results:
        print(f"[{r['source']}] seen={r['seen']} new={r['new']} "
              f"high_ticket={r['high_ticket']} skipped_304={r['skipped_304']}")
    print(f"done in {time.monotonic() - started:.1f}s")
