# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The priority score: what to look at first, and why.

Each CVE is scored by named rules, and every rule that fires records its
evidence. The band is set by the strongest rule, as Recorded Future's risk
rules work; other rules only nudge the score within that band. A watched
vendor (from the CVE record's affected list) lifts the band by one.

Severity on its own reaches MEDIUM at most (Neko, 19 October 2026): a
critical CVE on any vendor still surfaces once there is exploitation or
exploit evidence. HIGH TICKET is band HIGH or above, recomputed on every
check, so it can drop as well as rise.

score_cve() and score_article() are pure, so the tests and the point-in-time
backtest exercise exactly the rules the live check uses.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import cverecord
import db
import extract

BANDS = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
NONE, LOW, MEDIUM, HIGH, CRITICAL = range(5)
HIGH_TICKET_BAND = HIGH

REPORT_DECAY_DAYS = 30       # a reported-exploited claim this old, not in KEV, drops a band
TRENDING_DAYS = 7
TRENDING_SOURCES = 3
ROUNDUP_CVES = 5             # an article naming more is a roundup


def _band_of(rules: list[tuple[int, str]]) -> int:
    return max((b for b, _ in rules), default=NONE)


def _score(band: int, rules: list[tuple[int, str]]) -> int:
    """band * 100, plus a nudge from the other rules that fired, never
    reaching the next band."""
    extra = sorted((b for b, _ in rules), reverse=True)[1:]
    return band * 100 + min(99, sum(8 * b for b in extra))


def score_cve(f: dict) -> tuple[int, str, list[str]]:
    """(score, band, evidence) for one CVE from its facts. Every key is
    optional; a missing fact simply doesn't fire its rule."""
    rules: list[tuple[int, str]] = []
    if f.get("kev"):
        ransom = ", ransomware use known" if f.get("kev_ransomware") == "Known" else ""
        rules.append((CRITICAL, f"CISA KEV since {f.get('kev_date') or 'unknown date'}{ransom}"))
    if f.get("ssvc_exploitation") == "active":
        rules.append((CRITICAL, "CISA SSVC: exploitation active"))
    if f.get("reports"):
        days = f.get("last_report_days")
        if not f.get("kev") and days is not None and days > REPORT_DECAY_DAYS:
            rules.append((MEDIUM, f"exploitation reported by {f['reports']} source(s), last {days} days ago"))
        else:
            rules.append((HIGH, f"exploitation reported by {f['reports']} source(s)"))
    if f.get("metasploit"):
        rules.append((HIGH, "Metasploit exploit module"))
    pct = f.get("epss_percentile")
    if pct is not None and pct >= 0.95:
        rules.append((HIGH, f"EPSS {pct * 100:.0f}th percentile"))
    if f.get("nuclei"):
        rules.append((MEDIUM, "Nuclei template"))
    if f.get("poc_repo"):
        rules.append((MEDIUM, "public PoC repo"))
    if f.get("ssvc_exploitation") == "poc":
        rules.append((MEDIUM, "CISA SSVC: proof of concept"))
    cvss = f.get("cvss")
    if cvss is not None:
        src = f" {f['cvss_source']}" if f.get("cvss_source") else ""
        if cvss >= 9:
            rules.append((MEDIUM, f"CVSS {cvss}{src}"))
        elif cvss >= 7:
            rules.append((LOW, f"CVSS {cvss}{src}"))
    if (f.get("sources_7d") or 0) >= TRENDING_SOURCES:
        rules.append((MEDIUM, f"covered by {f['sources_7d']} sources in {TRENDING_DAYS} days"))
    if f.get("poc_mentioned") and not f.get("poc_repo"):
        rules.append((LOW, "coverage describes a PoC"))

    band = _band_of(rules)
    why = [text for _, text in sorted(rules, key=lambda r: -r[0])]
    if f.get("watch_terms"):
        band = min(CRITICAL, band + 1)
        why.append(f"watchlist: {', '.join(f['watch_terms'])} (one band up)")
    return _score(band, rules) if rules else (band * 100), BANDS[band], why


# Words in vendor and product names too generic to say what a title is about.
_GENERIC_WORDS = {
    "corporation", "corp", "inc", "ltd", "limited", "llc", "gmbh", "company", "enterprise", "software",
    "systems", "networks", "technologies", "technology", "foundation", "project", "group", "services",
    "server", "client", "data", "center", "cloud", "security", "platform", "manager", "management",
    "suite", "edition", "community", "open", "source", "framework", "library", "plugin", "module",
    "core", "application", "applications", "tools", "toolkit", "with", "for", "the", "and",
}
_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9.+-]{3,}")


def names_subject(cve_id: str, title: str, names: list[str], structured: bool = False) -> bool:
    """Whether a CVE is what the article is about, not a passing mention: a
    one-CVE advisory (KEV, GHSA), the CVE ID in the title, or a distinctive
    word of an affected vendor or product (or, with no record, a watchlist
    term) in the title."""
    if structured or cve_id.upper() in title.upper():
        return True
    lowered = title.lower()
    for name in names:
        for word in _WORD_RE.findall(name):
            w = word.lower().strip(".+-")
            if len(w) >= 4 and w not in _GENERIC_WORDS and re.search(rf"\b{re.escape(w)}\b", lowered):
                return True
    return False


def score_article(cve_scores: list[tuple[int, str, list[str], str]], *, n_cves: int,
                  subjects: set[str] | None = None, title_claim: bool = False,
                  tracked: list[str] = (), breach: bool = False) -> tuple[int, str, list[str]]:
    """(score, band, evidence) for an article: its strongest CVE, plus what
    the article itself says. cve_scores holds (score, band, evidence, cve_id).

    A CVE gives its full band only when it is the article's subject
    (`subjects`; None means all are): a story mentioning an old KEV CVE in
    passing isn't news about it, so a passing mention counts at MEDIUM at most.
    A roundup naming more than ROUNDUP_CVES CVEs is capped at MEDIUM the same
    way: each one surfaces through its own advisory or report instead."""
    rules: list[tuple[int, str]] = []
    best = max(cve_scores, default=None)
    if best:
        about = [c for c in cve_scores if subjects is None or c[3] in subjects]
        top = max(about, default=None)
        band = BANDS.index(top[1]) if top else NONE
        if top and n_cves > ROUNDUP_CVES and band > MEDIUM:
            rules.append((MEDIUM, f"roundup naming {n_cves} CVEs, strongest {top[3]} ({top[1]})"))
        elif top and band:
            rules.append((band, f"{top[3]}: " + "; ".join(top[2])))
        if best is not top and BANDS.index(best[1]) > band:
            rules.append((min(MEDIUM, BANDS.index(best[1])), f"mentions {best[3]} ({best[1]}) in passing"))
    if title_claim:
        rules.append((HIGH, "headline reports exploitation"))
    if tracked:
        rules.append((HIGH, f"tracked: {', '.join(tracked)}"))
    if breach:
        rules.append((MEDIUM, "breach reported"))
    band = _band_of(rules)
    return _score(band, rules), BANDS[band], [text for _, text in sorted(rules, key=lambda r: -r[0])]


def gather_cve_facts(conn, watchlist: dict[str, list[str | dict]]) -> dict[str, dict]:
    """Every captured CVE's facts, in a handful of bulk queries."""
    now = datetime.now(timezone.utc)
    facts: dict[str, dict] = {cve: {} for cve in db.all_cve_ids(conn)}
    for r in conn.execute("SELECT * FROM cve_scores"):
        f = facts.get(r["cve_id"])
        if f is None:
            continue
        cvss, source = r["nvd_base_score"], None
        if cvss is None and r["rec_base_score"] is not None:
            cvss, source = r["rec_base_score"], ("CNA" if r["rec_score_source"] == "CNA" else "CISA")
        f.update(kev=bool(r["kev_listed"]), kev_date=r["kev_date_added"], kev_ransomware=r["kev_ransomware"],
                 epss_percentile=r["epss_percentile"], ssvc_exploitation=r["ssvc_exploitation"],
                 cvss=cvss, cvss_source=source)
    for cve, n, last in conn.execute(
        "SELECT r.cve_id, COUNT(DISTINCT a.source_id), MAX(COALESCE(a.published_at, a.fetched_at)) "
        "FROM cve_exploit_reports r JOIN articles a ON a.id = r.article_id GROUP BY r.cve_id"
    ):
        if cve in facts:
            facts[cve]["reports"] = n
            facts[cve]["last_report_days"] = _days_since(last, now)
    for cve, kind in conn.execute("SELECT DISTINCT cve_id, kind FROM cve_coverage"):
        if cve in facts:
            facts[cve][kind] = True
    for (cve,) in conn.execute("SELECT DISTINCT cve_id FROM cve_pocs"):
        if cve in facts:
            facts[cve]["poc_repo"] = True
    for cve in db.get_poc_mention_cve_ids(conn):
        if cve in facts:
            facts[cve]["poc_mentioned"] = True
    since = (now - timedelta(days=TRENDING_DAYS)).isoformat()
    marks = ", ".join("?" for _ in db.STRUCTURED_SOURCES)
    for cve, n in conn.execute(
        "SELECT m.cve_id, COUNT(DISTINCT a.source_id) FROM cve_mentions m "
        "JOIN articles a ON a.id = m.article_id JOIN sources s ON s.id = a.source_id "
        f"WHERE s.name NOT IN ({marks}) AND COALESCE(a.published_at, a.fetched_at) >= ? GROUP BY m.cve_id",
        (*db.STRUCTURED_SOURCES, since),
    ):
        facts[cve]["sources_7d"] = n
    for cve, terms in cverecord.watchlist_terms(conn, list(facts), watchlist).items():
        facts[cve]["watch_terms"] = terms
    return facts


def _days_since(iso: str | None, now: datetime) -> int | None:
    try:
        then = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (now - then).days


def recompute(conn) -> dict:
    """Score every CVE and article, and set high_ticket from the band. Runs
    at the end of every check's refresh."""
    watchlist, _, _ = extract.load_filters()
    facts = gather_cve_facts(conn, watchlist)
    cve_rows = {cve: score_cve(f) for cve, f in facts.items()}
    db.replace_cve_priority(conn, [(c, s, b, json.dumps(w)) for c, (s, b, w) in cve_rows.items()])

    mentions: dict[int, list[str]] = {}
    for aid, cve in conn.execute("SELECT article_id, cve_id FROM cve_mentions"):
        mentions.setdefault(aid, []).append(cve)
    tracked: dict[int, list[str]] = {}
    for aid, name in conn.execute(
        "SELECT article_id, entity_name FROM entity_matches UNION SELECT article_id, campaign_name FROM campaign_matches"
    ):
        tracked.setdefault(aid, []).append(name)

    # Names that say what a CVE is: the record's vendors and products, else
    # its watchlist terms (which came from small articles' titles).
    affected = db.get_cve_affected(conn, list(facts))
    names = {c: [" ".join(pair) for pair in affected.get(c, [])] or facts[c].get("watch_terms", []) for c in facts}

    updates = []
    for row in conn.execute(
        "SELECT a.id, a.title, a.is_breach, s.name AS source FROM articles a JOIN sources s ON s.id = a.source_id"
    ):
        title = row["title"] or ""
        cves = sorted(set(mentions.get(row["id"], [])))
        scored = [(*cve_rows[c], c) for c in cves if c in cve_rows]
        structured = row["source"] in db.STRUCTURED_SOURCES
        subjects = {c for c in cves if names_subject(c, title, names.get(c, []), structured)}
        title_claim, _ = extract.exploitation_evidence(title, "")
        score, band, why = score_article(scored, n_cves=len(cves), subjects=subjects, title_claim=title_claim,
                                         tracked=sorted(set(tracked.get(row["id"], []))), breach=bool(row["is_breach"]))
        updates.append((score, band, json.dumps(why), int(BANDS.index(band) >= HIGH_TICKET_BAND), row["id"]))
    db.set_article_priorities(conn, updates)
    return {"high_ticket_now": sum(u[3] for u in updates), "articles_scored": len(updates),
            "cves_scored": len(cve_rows)}
