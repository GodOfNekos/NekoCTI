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
#
# Any common dash, any case (23 September 2026). Publishers' CMSes swap in
# typographic dashes: a Cybereason table wrote "CVE‑2024‑40762" with
# non-breaking hyphens (U+2011), and NVD links carry lowercase
# "cve-2025-...". The ASCII-only, uppercase-only version missed 7 mentions
# across 5 Prod articles, three of them KEV-listed CVEs. Every match goes
# through normalize_cve() so the stored id is always CVE-YYYY-NNNN.
_CVE_DASHES = "\\-\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63\uff0d"
CVE_RE = re.compile(rf"CVE[{_CVE_DASHES}]\d{{4}}[{_CVE_DASHES}]\d{{4,7}}", re.IGNORECASE)
_NON_ASCII_DASH_RE = re.compile(rf"[{_CVE_DASHES[2:]}]")


def normalize_cve(raw: str) -> str:
    """The canonical CVE-YYYY-NNNN form of a CVE_RE match."""
    return _NON_ASCII_DASH_RE.sub("-", raw).upper()

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
        cve_id = normalize_cve(match.group(0))
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


# Real-world exploitation, which is a different claim from "a PoC exists"
# (Neko's point, 22 September 2026): exploit code being public says nothing
# about whether anyone is actually using it, and a vulnerability can be
# exploited in the wild with no public PoC at all.
#
# CISA KEV is the authoritative answer and is recorded per CVE by enrich.py,
# but it lags: reporting routinely says "actively exploited" days or weeks
# before an entry is added, and plenty of real exploitation never gets a KEV
# entry. This catches what the captured coverage itself states.
#
# Deliberately narrow. "Exploited" alone is far too common in vulnerability
# writeups describing what an attacker *could* do, so every branch requires
# wording that asserts real use: an in-the-wild/active qualifier, an
# observed-attacks phrasing, or a zero-day being exploited. Conditional and
# hypothetical framings ("could be exploited", "if exploited", "may allow an
# attacker to exploit") are excluded by the negation check below.
_EXPLOITED_WILD_RE = re.compile(
    r"\b("
    r"(?:actively |currently |being )?exploited in the wild|"
    r"in[- ]the[- ]wild exploitation|"
    r"under (?:active )?(?:attack|exploitation)|"
    r"actively (?:being )?exploited|"
    r"exploitation (?:has been |was |is )?(?:actively )?(?:observed|detected|seen|reported|ongoing)|"
    r"observed (?:active )?exploitation|"
    r"evidence of (?:active )?exploitation|"
    r"exploited (?:as |in )(?:a )?zero[- ]day|"
    r"zero[- ]day (?:attack|exploitation)|"
    r"weaponized in (?:real[- ]world )?attacks|"
    r"used in (?:real[- ]world |active |ongoing )?attacks|"
    r"attackers? (?:are |have been |were )(?:actively )?exploiting|"
    r"threat actors? (?:are |have been |were )(?:actively )?exploiting|"
    r"added to (?:CISA'?s? )?(?:known exploited vulnerabilities|KEV)"
    r")\b",
    re.IGNORECASE,
)

# Conditional framing, checked in the words immediately before a match:
# "could be exploited in the wild" is a warning, not a report.
_EXPLOITED_NEGATION_RE = re.compile(
    r"\b(no|not|n't|without|could|would|might|may|if|unless|potential(?:ly)?|"
    r"risk of|warns? of|before it is|prevent)\b(?:\s+\w+){0,3}\s*$",
    re.IGNORECASE,
)


# An exploitation claim is attached to a CVE when both appear in the same
# sentence. Tuned against real data on 22 September 2026, scoring each
# candidate rule by how well it agreed with CISA KEV (the authoritative
# answer to the same question) across every captured article:
#
#   same sentence   197 CVEs, 74% in KEV   <- chosen
#   sentence +/-1   211 CVEs, 73% in KEV
#   600-char window  80 CVEs, 59% in KEV
#
# The character window was both less precise and less complete: in a monthly
# roundup it attached a claim to whichever CVE happened to sit nearby, while
# missing list-formatted reports where the sentence is long. Sentence
# scoping also drops the general commentary that an article-level flag
# caught ("zero-day exploitation minimises detection", or a vendor blog
# using "an actively exploited Chrome vulnerability" as a worked example),
# because those sentences name no CVE.
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def _exploitation_matches(text: str):
    """Every exploitation phrase in the text that survives the conditional
    check ("could be exploited" is a warning, not a report)."""
    for m in _EXPLOITED_WILD_RE.finditer(text):
        window_before = text[max(0, m.start() - 40):m.start()]
        if _EXPLOITED_NEGATION_RE.search(window_before):
            continue
        yield m


def exploitation_evidence(title: str, body_text: str) -> tuple[bool, set[str]]:
    """Reported real-world exploitation, as (title_claim, cve_ids).

    `cve_ids` are the CVEs this text actually claims are being exploited:
    a CVE ID named in the same sentence as an exploitation phrase.
    `title_claim` is True when the headline itself reports
    exploitation, which is a deliberate second route: a headline like
    "Cisco warns of actively exploited zero-day" is a real report even before
    the CVE is named further down.

    Deliberately not a whole-article flag: a monthly patch roundup mentioning
    that two of ninety CVEs are exploited should mark those two, not tar the
    other eighty-eight."""
    text = title + " " + body_text
    title_claim = any(True for _ in _exploitation_matches(title))

    cve_ids: set[str] = set()
    for sentence in _SENTENCE_SPLIT_RE.split(text):
        if any(True for _ in _exploitation_matches(sentence)):
            cve_ids.update(normalize_cve(m.group(0)) for m in CVE_RE.finditer(sentence))
    return title_claim, cve_ids


def exploited_in_wild(title: str, body_text: str) -> bool:
    """True when this text reports real exploitation of a named CVE, or says
    so in its own headline. Kept as the article-level flag; the per-CVE
    detail comes from exploitation_evidence()."""
    title_claim, cve_ids = exploitation_evidence(title, body_text)
    return bool(title_claim or cve_ids)
