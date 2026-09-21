"""Regex extraction and watchlist/tag matching against article text.

Only the deterministic, fixed-pattern wins live here (CVE IDs, explicit
CVSS scores, keyword/alias matching) -- see the vault note's own "Not
doing" list. The genuinely nuanced part (MITRE ATT&CK technique tagging,
APT/TTP inference) is deliberately deferred to Phase 2's LLM classification
pass, since that's exactly where regex/keyword matching falls short.

HIGH_TICKET_CVSS_THRESHOLD is the "high ticket" tier's severity bar,
independent of the vendor watchlist -- a critical CVE on an unwatched
vendor still surfaces in the digest.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
WATCHLIST_PATH = HERE / "watchlist.json"
TAGS_PATH = HERE / "tags.json"
CAMPAIGNS_PATH = HERE / "campaigns.json"

HIGH_TICKET_CVSS_THRESHOLD = 9.0

# CVE-YYYY-NNNNN (4-7 digit sequence number, per the real format).
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# Matches the real pattern confirmed against The Hacker News's own feed,
# 16 September 2026: "CVE-2026-5430 (CVSS score: 9.8/10.0)". A couple of
# common phrasing variants are covered too, but this isn't meant to catch
# every possible way severity could be written -- that's what Phase 2's
# LLM classification pass is for.
CVSS_RE = re.compile(
    r"CVSS(?:\s+score)?(?:\s+of)?:?\s*([0-9]+(?:\.[0-9]+)?)\s*(?:/\s*10(?:\.0)?)?",
    re.IGNORECASE,
)


def extract_cves(text: str) -> list[tuple[str, float | None]]:
    """Return one (cve_id, cvss_score) pair per distinct CVE found in text.

    A real article mentions the same CVE ID several times (once in the
    lede, again in a details list, again in a table) -- found live against
    a real Chrome V8 zero-day article, 16 September 2026, which produced
    16 raw regex matches for what was genuinely a much smaller set of
    distinct CVEs. Deduped here by keeping the first CVSS score seen for
    each id, so a later score-less mention of an already-scored CVE
    doesn't overwrite it.

    A CVSS score is only ever attached to a CVE mention if it appears
    within a short window after it -- otherwise a single CVSS score
    somewhere else in a multi-CVE article could get wrongly attributed to
    every CVE found.
    """
    scores: dict[str, float | None] = {}
    order: list[str] = []
    for match in CVE_RE.finditer(text):
        cve_id = match.group(0)
        window = text[match.end(): match.end() + 60]
        cvss_match = CVSS_RE.search(window)
        score = float(cvss_match.group(1)) if cvss_match else None

        if cve_id not in scores:
            scores[cve_id] = score
            order.append(cve_id)
        elif scores[cve_id] is None and score is not None:
            scores[cve_id] = score

    return [(cve_id, scores[cve_id]) for cve_id in order]


def load_watchlist() -> dict[str, list[str]]:
    data = json.loads(WATCHLIST_PATH.read_text(encoding="utf-8"))
    return data.get("vendors", {})


def load_tags() -> list[dict]:
    data = json.loads(TAGS_PATH.read_text(encoding="utf-8"))
    return data.get("entities", [])


def load_campaigns() -> list[dict]:
    if not CAMPAIGNS_PATH.exists():
        return []
    data = json.loads(CAMPAIGNS_PATH.read_text(encoding="utf-8"))
    return data.get("campaigns", [])


def match_vendors(text: str, watchlist: dict[str, list[str]]) -> list[tuple[str, str]]:
    """Case-insensitive whole-term matching against the vendor watchlist.

    Returns (category, term) pairs for every real match. Multiple terms
    from the same category can all match independently -- this tags
    relevance, it never discards anything.
    """
    lowered = text.lower()
    matches: list[tuple[str, str]] = []
    for category, terms in watchlist.items():
        for term in terms:
            pattern = r"\b" + re.escape(term.lower()) + r"\b"
            if re.search(pattern, lowered):
                matches.append((category, term))
    return matches


def match_entities(text: str, tags: list[dict]) -> list[str]:
    """Case-insensitive matching against tracked entities and their aliases.

    Each tag entry is expected to look like {"name": str, "aliases": [str, ...]}.
    Returns the canonical `name` for every entity found, deduplicated.
    """
    lowered = text.lower()
    found: list[str] = []
    for tag in tags:
        name = tag.get("name", "")
        aliases = tag.get("aliases", [])
        for candidate in [name, *aliases]:
            if not candidate:
                continue
            pattern = r"\b" + re.escape(candidate.lower()) + r"\b"
            if re.search(pattern, lowered):
                found.append(name)
                break
    return found


def match_campaigns(text: str, campaigns: list[dict]) -> list[str]:
    """Same matching shape as match_entities -- campaigns are tracked the
    same way as APT/entities (a name plus aliases, case-insensitive whole-
    term matching), just a distinct category: a campaign (ClickFix,
    ConsentFix, a specific RAT) is a technique/tooling name, not an actor,
    so it gets its own tab and its own tracked-list rather than being
    folded into APT/Entities."""
    lowered = text.lower()
    found: list[str] = []
    for campaign in campaigns:
        name = campaign.get("name", "")
        aliases = campaign.get("aliases", [])
        for candidate in [name, *aliases]:
            if not candidate:
                continue
            pattern = r"\b" + re.escape(candidate.lower()) + r"\b"
            if re.search(pattern, lowered):
                found.append(name)
                break
    return found


def is_high_ticket(cve_mentions: list[tuple[str, float | None]]) -> bool:
    return any(score is not None and score >= HIGH_TICKET_CVSS_THRESHOLD
               for _, score in cve_mentions)


# Keyword-based, not exhaustive -- a real breach story ("X confirms breach,
# Y million records exposed") reads differently from a vulnerability
# disclosure ("a flaw could allow unauthorized access"), and a first version
# of this regex didn't distinguish the two: "unauthorized access to" and
# "compromised the network" both show up constantly in hypothetical
# vulnerability-impact language, not just real incident reports. Found by
# actually reading the real matches after the first backfill (16 September
# 2026), not assumed correct from the pattern alone - roughly half of the
# first pass's 14 matches were false positives, including two weekly
# roundup digests (which aggregate many stories and can never themselves be
# "a breach") and several plain CVE-disclosure articles.
#
# A negative lookbehind for a "could/may" frame right before the phrase
# was tried first and didn't actually help: real vulnerability-impact
# sentences read "could result in unauthorized access", not "could
# unauthorized access" - the hedge word and the trigger phrase are rarely
# adjacent, so a one-word lookbehind never fires. The two phrases doing
# the real damage ("unauthorized access to", "compromised the network")
# are simply too generic - they show up constantly in pure vulnerability
# writeups describing hypothetical impact - so they're dropped entirely
# rather than patched further, trading some recall for real precision on
# what's meant to be a "major breaches" section, not a vulnerability list.
_BREACH_RE = re.compile(
    r"\b("
    r"data breach|breached|breach of|confirms? (?:a )?breach|"
    r"(?:hacked|hack) (?:into|of)|suffers? a hack|"
    r"data leak|leaked database|exposed database|"
    r"records? (?:were |was )?exposed|exposed records|"
    r"stolen data|data (?:was |were )?stolen|"
    r"ransomware attack (?:on|against|hit)|hit by ransomware|"
    r"disclosed a (?:data )?breach|security incident (?:affecting|involving)"
    r")\b",
    re.IGNORECASE,
)

_ROUNDUP_TITLE_RE = re.compile(r"^(weekly recap|threatsday|⚡)", re.IGNORECASE)


def is_breach(title: str, body_text: str) -> bool:
    if _ROUNDUP_TITLE_RE.search(title.strip()):
        return False
    return bool(_BREACH_RE.search(title + " " + body_text))


# Catches real coverage of a PoC/exploit's existence in an article's own
# text - deliberately separate from the `nomi-sec/PoC-in-GitHub` lookup
# (pocs.py), which can only ever see a PoC that's a real public GitHub
# repo. A researcher demonstrating a working exploit in a blog post
# without releasing code, an exploit sold privately, or a brand-new CVE
# nomi-sec's own indexer hasn't caught up to yet are all real gaps that
# lookup can't cover but this text signal can, since NekoCTI already
# ingests the real coverage where that kind of mention would appear.
#
# Phrasing chosen to require a concrete claim that an exploit/PoC
# artifact exists or was demonstrated, not just abstract exploitability
# language ("could be exploited", "may allow an attacker to exploit
# this") - the same false-positive lesson already learned building the
# breach classifier: a phrase common in hypothetical-impact writing reads
# very differently from one only used to describe a real, concrete thing.
#
# Two real false-positive classes found reading the actual first-pass
# matches (16 September 2026), not assumed correct from the pattern
# alone: (1) negation - "no public exploit code" and "do not publish
# exploit code" both matched the bare phrase despite asserting the
# opposite of what this is meant to detect, so every match now gets a
# real negation check against the text immediately before it, unlike the
# breach classifier's own negative-lookbehind attempt (which didn't work
# there because the hedge word and trigger phrase weren't adjacent) -
# here a negation word like "no"/"not" genuinely does sit right before
# the phrase it negates, so a short lookbehind window works. (2) "proof-
# of-concept" used in two unrelated senses - a research project's own
# development-maturity stage ("fuzzlab is at the proof-of-concept
# stage"), and attacker-chosen decoy account names styled like
# "proof-of-concept" test accounts - neither is a claim that a real
# exploit/PoC exists, so those two specific continuations are excluded
# by name rather than guessed at broadly. (3) "Exploit Code Maturity" is
# a real, fixed CVSS temporal-metric field name that shows up constantly
# in vulnerability writeups regardless of its actual rated value - often
# "Unproven", the literal opposite of what this is meant to detect - so
# the metric name itself is excluded too, not just its "no exploit
# exists" phrasing.
_POC_MENTION_RE = re.compile(
    r"\b("
    r"proof[- ]of[- ]concept(?! (?:names?|stage|phase))|"
    r"\bpoc\b|"
    r"exploit code(?! maturity)|"
    r"working exploit|"
    r"exploit (?:has been |was |is )?(?:publicly )?(?:released|published|available|demonstrated)|"
    r"(?:released|published) (?:a |an )?(?:public )?exploit|"
    r"exploit demonstrat\w*|"
    r"researchers? (?:have |has )?(?:demonstrated|published|released) (?:a |an )?(?:working )?exploit"
    r")\b",
    re.IGNORECASE,
)

_POC_NEGATION_RE = re.compile(
    r"\b(no|not|n't|without|neither|lack of)\b(?:\s+\w+){0,2}\s*$", re.IGNORECASE
)


def mentions_poc(title: str, body_text: str) -> bool:
    text = title + " " + body_text
    for m in _POC_MENTION_RE.finditer(text):
        window_before = text[max(0, m.start() - 25):m.start()]
        if _POC_NEGATION_RE.search(window_before):
            continue
        return True
    return False
