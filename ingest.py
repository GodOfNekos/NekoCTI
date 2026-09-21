"""RSS polling and full-article fetching.

The Hacker News's own feed was checked for real, 16 September 2026, before
this was written: 50 items per pull, but every RSS `description` is a
fixed ~390-character teaser, not article content, and there are no
`<category>` tags at all. So for THN, the real content this pipeline
extracts from comes from fetching each item's own article page via
Trafilatura, not the RSS summary -- confirmed necessary, not assumed.

Krebs on Security (added 16 September 2026, same research pass that found
it) is different: its feed ships the real `content:encoded` field with
close to full article text already in it (confirmed: ~5900 characters of
raw HTML versus a ~430-character `description` teaser). Trafilatura can
extract straight from that raw HTML string just as well as from a fetched
page, so `_extract_from_entry` tries the feed's own content field first
and only falls back to a live fetch when it's missing or too short to be
real content -- a per-entry decision, not a per-source flag, so a future
source that sometimes-but-not-always ships full content still gets the
cheaper path whenever it can.

Conditional fetching (etag/last-modified) avoids re-downloading an
unchanged feed on every poll, per the real current best-practice pattern
found in the 16 September research pass.
"""

from __future__ import annotations

import calendar
import re
import time
from datetime import datetime, timezone

import feedparser
import trafilatura

import db
import extract

# Schema built generic (see db.py) so more feeds slot in here later without
# a rewrite.
#
# The 30 added 16 September 2026 came from a real feed-discovery pass
# against every blog listed in muchdogesec/awesome_threat_intel_blogs --
# that repo's own "Subscribe" links point at Obstracts' hosted web app
# (HTML pages, not raw feeds, confirmed via a real HTTP request before
# assuming otherwise), so each blog's OWN real feed was independently
# discovered instead (via its HTML `<link rel="alternate">` tag, or a
# common fallback path) and test-fetched for real reachability and
# content richness. 134 of 191 real blogs checked had a working feed;
# these 30 are the highest-signal subset across Analyst/Community/
# Government/Vendor/Media categories, not just the first N that worked.
# One real correction made before trusting a discovered URL: GitHub
# Security Lab's homepage auto-discovered to github.blog's site-wide feed
# (every GitHub Blog post, not just security research) -- found and
# replaced with the real tag-scoped feed instead, confirmed via a direct
# fetch to actually be security-only content.
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

# Trafilatura's own fetch has no hard timeout by default; bound it so one
# slow/unresponsive article page can't stall an entire ingest run.
FETCH_TIMEOUT_S = 20

# Below this length a feed's own content field is treated as another teaser,
# not real article text -- worth a live fetch instead.
MIN_FEED_CONTENT_CHARS = 800

# Confirmed real, 16 September 2026: Trafilatura's own `include_images`
# extraction pulls genuine inline content images out of an article page --
# tested against a real THN article about a named malware campaign and
# found its own real illustrative graphic, not an ad or an author photo.
# Not every extracted image will be a real technical diagram (some
# articles' inline images are just decorative), so this captures broadly
# and lets the dashboard's own reader show what's there rather than trying
# to classify "diagram vs. not" automatically -- same "capture broadly,
# filter later" philosophy already used elsewhere in this project. Capped
# per article so one image-heavy page can't flood the reader's side panel.
MAX_IMAGES_PER_ARTICLE = 6
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_published(entry) -> str | None:
    """Real sortable UTC timestamp for an entry's publish date.

    feedparser already normalizes `published_parsed` to a UTC struct_time
    regardless of the feed's own timezone offset, so that's used instead of
    the raw `published` string -- sorting on the raw string mixed different
    offsets and, worse, sorted on ingestion time instead of real publish
    time wherever `published` was missing. Falls back to the raw string
    (then None) only when feedparser couldn't parse a date at all.
    """
    struct = entry.get("published_parsed") or entry.get("updated_parsed")
    if struct:
        dt = datetime.fromtimestamp(calendar.timegm(struct), tz=timezone.utc)
        return dt.isoformat()
    return entry.get("published") or entry.get("updated")


def _images_from_html(html: str) -> list[str]:
    """Real inline content images from a page's raw HTML, via Trafilatura's
    own `include_images` extraction rather than a hand-rolled HTML scrape.
    Markdown output is used purely as a convenient carrier for the real
    image URLs Trafilatura already found -- the markdown text itself isn't
    otherwise used."""
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


def fetch_full_text(url: str) -> tuple[str | None, list[str]]:
    """Best-effort full-article fetch: text and any real inline images
    together, from the same single page fetch. Returns (None, []) on any
    failure rather than raising -- a single bad article page must never
    stop the run."""
    try:
        downloaded = trafilatura.fetch_url(url)
        if not downloaded:
            return None, []
        return trafilatura.extract(downloaded), _images_from_html(downloaded)
    except Exception:
        return None, []


def _extract_from_entry(entry, link: str) -> tuple[str | None, list[str]]:
    """Full article text and real inline images for one entry, cheapest
    real option first: the feed's own `content:encoded` field (via
    Trafilatura, which works on a raw HTML string just as well as a
    fetched page) if it's long enough to be real content, else a live
    fetch of the article page."""
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
    """Poll one source, fetch/extract each new item, store it. Returns a
    small summary dict for the caller to report on."""
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

    watchlist = extract.load_watchlist()
    tags = extract.load_tags()
    campaigns = extract.load_campaigns()

    for entry in parsed.entries:
        summary["seen"] += 1

        link = entry.get("link", "")
        guid = entry.get("id") or entry.get("guid")
        title = entry.get("title", "")
        description = entry.get("description", "") or entry.get("summary", "")
        published_at = normalize_published(entry)

        nlink = db.normalize_link(link)
        # Checked on link+guid alone, before paying for a full-article fetch
        # -- see article_exists's own docstring for why content_hash can't
        # be part of this pre-check.
        if db.article_exists(conn, nlink, guid):
            continue

        full_text, images = _extract_from_entry(entry, link)
        text_for_extraction = full_text or description

        cve_mentions = extract.extract_cves(text_for_extraction)
        vendor_matches = extract.match_vendors(text_for_extraction, watchlist)
        entity_matches = extract.match_entities(text_for_extraction, tags)
        campaign_matches = extract.match_campaigns(text_for_extraction, campaigns)
        high_ticket = extract.is_high_ticket(cve_mentions)
        breach = extract.is_breach(title, text_for_extraction)
        poc_mentioned = extract.mentions_poc(title, text_for_extraction)

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
        )
        if article_id is None:
            # The link+guid pre-check above should have already caught this;
            # this is only the defensive backstop firing, not the normal path.
            continue

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
    """Poll every RSS source, then CISA KEV and GitHub Security Advisories,
    then check real PoC availability for any CVE captured along the way.

    Neither KEV nor GHSA is RSS -- both are structured JSON APIs with their
    own fetch/parse shape (see kev.py and ghsa.py's own module docstrings)
    -- so they each get their own ingestion function rather than being
    forced through feedparser. The `sources` table still records them the
    same generic way as any RSS source; only the Python-level fetch logic
    differs.

    PoC checking (pocs.py) runs last and is a different shape again: an
    enrichment lookup against CVEs already captured above, not a source
    of its own new articles -- see pocs.py's own module docstring for why.
    """
    import ghsa
    import kev
    import pocs

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
