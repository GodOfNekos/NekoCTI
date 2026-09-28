"""Digest generation and vault delivery.

Groups what's new into high-ticket items, watchlist/tracked-entity matches,
and everything else, then writes it to the vault's daily note -- the
delivery layer the plan calls for before any dashboard or Voice Line
integration gets built.

Time-window filtering happens in Python, not via SQLite's own datetime()
comparison against the stored ISO-with-offset timestamps -- the two string
formats don't line up cleanly (SQLite's datetime('now') has no 'T'
separator or offset suffix), so a string comparison between them would be
fragile. Parsing with datetime.fromisoformat() and comparing real datetime
objects sidesteps that entirely.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Overridable so a containerized deploy can point this at a mounted volume
# (e.g. /app/vault-daily-notes) instead of the host's own home directory,
# which means something different from inside a container -- Path.home()
# there resolves to the container user's home, not Neko's real vault.
# Bare-metal runs (the default here) are unaffected.
VAULT_DAILY_NOTES = Path(os.environ.get(
    "VAULT_DAILY_NOTES_PATH",
    str(Path.home() / "Documents" / "Projects" / "01 - Daily Notes"),
))

# Bounds how many rows get pulled before Python-side time filtering --
# plenty of headroom for a single day's ingest volume without loading an
# ever-growing table in full as the archive ages.
RECENT_ROW_LIMIT = 500


def _today_note_path() -> Path:
    return VAULT_DAILY_NOTES / f"{datetime.now().strftime('%Y-%m-%d')}.md"


MAX_VENDORS_SHOWN = 3

# Neko's rule: no em dashes in anything written for them. Titles come from
# feeds as published, so an em dash (U+2014) in one becomes a spaced hyphen
# (28 September 2026, when one reached the note). The dashboard is unchanged.
_EM_DASH = re.compile(r"\s*" + chr(0x2014) + r"\s*")


def _format_line(conn, row) -> str:
    """One compact line per article: title, then a short CVE/vendor/entity
    note. Counts and the highest severity found, not every CVE ID and every
    vendor term spelled out -- a real first version of this dumped the full
    detail (one article had 55 raw CVE mentions), which was accurate but too
    long to actually glance at daily. Compacted 16 September 2026 at Neko's
    request, after reading a real digest and judging it too verbose.

    Whitespace in the title is collapsed to single spaces: some GitHub
    advisory titles carry line breaks and deep indentation, which split the
    markdown list item across lines in the vault note (24 September 2026).
    The dashboard never showed it because HTML collapses whitespace itself."""
    title = _EM_DASH.sub(" - ", " ".join((row["title"] or "").split()))
    bits = [f"- [{title}]({row['link']})"]

    cves = conn.execute(
        "SELECT cve_id, cvss_score FROM cve_mentions WHERE article_id = ?",
        (row["id"],),
    ).fetchall()
    if cves:
        if len(cves) == 1:
            c = cves[0]
            bits.append(f"{c['cve_id']}" + (f" (CVSS {c['cvss_score']})" if c["cvss_score"] else ""))
        else:
            scores = [c["cvss_score"] for c in cves if c["cvss_score"] is not None]
            note = f"{len(cves)} CVEs"
            if scores:
                note += f", highest CVSS {max(scores)}"
            bits.append(note)

    vendors = conn.execute(
        "SELECT DISTINCT vendor_term FROM vendor_matches WHERE article_id = ?",
        (row["id"],),
    ).fetchall()
    if vendors:
        terms = [v["vendor_term"] for v in vendors]
        shown = ", ".join(terms[:MAX_VENDORS_SHOWN])
        if len(terms) > MAX_VENDORS_SHOWN:
            shown += f" +{len(terms) - MAX_VENDORS_SHOWN} more"
        bits.append(f"vendors: {shown}")

    entities = conn.execute(
        "SELECT DISTINCT entity_name FROM entity_matches WHERE article_id = ?",
        (row["id"],),
    ).fetchall()
    if entities:
        bits.append(f"tracked: {', '.join(e['entity_name'] for e in entities)}")

    return "  ".join(bits)


def build_digest(conn, since_hours: int = 24) -> str:
    """Build a markdown digest of everything ingested in the last `since_hours`."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    all_recent = conn.execute(
        "SELECT * FROM articles ORDER BY fetched_at DESC LIMIT ?",
        (RECENT_ROW_LIMIT,),
    ).fetchall()
    rows = [r for r in all_recent if datetime.fromisoformat(r["fetched_at"]) >= cutoff]

    if not rows:
        return f"No new items in the last {since_hours}h."

    high_ticket = [r for r in rows if r["high_ticket"]]
    others = [r for r in rows if not r["high_ticket"]]

    watch_or_tagged: list = []
    plain: list = []
    for r in others:
        has_vendor = conn.execute(
            "SELECT 1 FROM vendor_matches WHERE article_id = ? LIMIT 1", (r["id"],)
        ).fetchone()
        has_entity = conn.execute(
            "SELECT 1 FROM entity_matches WHERE article_id = ? LIMIT 1", (r["id"],)
        ).fetchone()
        (watch_or_tagged if (has_vendor or has_entity) else plain).append(r)

    lines: list[str] = [f"{len(rows)} item(s) captured in the last {since_hours}h."]

    if high_ticket:
        lines.append("\n**High ticket:**")
        lines.extend(_format_line(conn, r) for r in high_ticket)

    if watch_or_tagged:
        lines.append("\n**Watchlist / tracked entity matches:**")
        lines.extend(_format_line(conn, r) for r in watch_or_tagged)

    if plain:
        lines.append(
            f"\n**Everything else**: {len(plain)} item(s) - no watchlist/entity "
            f"match, below the high-ticket threshold."
        )

    return "\n".join(lines)


def write_to_daily_note(digest_text: str) -> bool:
    """Append the digest to today's vault daily note.

    Deliberately does NOT create a new daily note if today's doesn't exist
    yet -- daily-note creation has its own vault-specific convention
    (frontmatter, an Index block, Session structure) that this script has
    no business replicating. Returns False if there was nothing to append
    to, so the caller can decide what to do about it.
    """
    path = _today_note_path()
    if not path.exists():
        return False

    timestamp = datetime.now().strftime("%I:%M %p").lstrip("0")
    section = f"\n## NekoCTI Digest - {timestamp}\n\n{digest_text}\n"

    with path.open("a", encoding="utf-8") as f:
        f.write(section)
    return True
