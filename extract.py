"""Regex extraction and watchlist/tag matching against article text.

Only fixed patterns live here (CVE IDs, explicit CVSS scores, keyword and
alias matching). ATT&CK tagging needs the LLM pass in attack.py.

HIGH_TICKET_CVSS_THRESHOLD is the high-ticket severity bar, independent of
the vendor watchlist: a critical CVE on an unwatched vendor still surfaces.
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

# CVE-YYYY-NNNN (4-7 digit sequence), any common dash, any case: publishers'
# CMSes swap in typographic dashes (U+2011 and friends) and NVD links are
# lowercase. Every match goes through normalize_cve() so the stored id is
# always CVE-YYYY-NNNN.
_CVE_DASHES = "\\-\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63\uff0d"
CVE_RE = re.compile(rf"CVE[{_CVE_DASHES}]\d{{4}}[{_CVE_DASHES}]\d{{4,7}}", re.IGNORECASE)
_NON_ASCII_DASH_RE = re.compile(rf"[{_CVE_DASHES[2:]}]")


def normalize_cve(raw: str) -> str:
    """The canonical CVE-YYYY-NNNN form of a CVE_RE match."""
    return _NON_ASCII_DASH_RE.sub("-", raw).upper()

# "CVE-2026-5430 (CVSS score: 9.8/10.0)" and a couple of common variants.
CVSS_RE = re.compile(
    r"CVSS(?:\s+score)?(?:\s+of)?:?\s*([0-9]+(?:\.[0-9]+)?)\s*(?:/\s*10(?:\.0)?)?",
    re.IGNORECASE,
)


def extract_cves(text: str) -> list[tuple[str, float | None]]:
    """One (cve_id, cvss_score) pair per distinct CVE in text.

    Articles repeat the same ID many times, so results are deduped, keeping
    the first score seen. A score is attached only when it appears within a
    short window after the ID, so one score in a multi-CVE article isn't
    attributed to every CVE.
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


def _load(path: Path, key: str, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8")).get(key, default)


def load_filters() -> tuple[dict[str, list[str]], list[dict], list[dict]]:
    """(watchlist vendors, tracked entities, tracked campaigns)."""
    return (_load(WATCHLIST_PATH, "vendors", {}), _load(TAGS_PATH, "entities", []),
            _load(CAMPAIGNS_PATH, "campaigns", []))


def match_vendors(text: str, watchlist: dict[str, list[str]]) -> list[tuple[str, str]]:
    """Case-insensitive whole-term matching against the vendor watchlist.
    Returns every matching (category, term) pair; it tags, never discards."""
    lowered = text.lower()
    matches: list[tuple[str, str]] = []
    for category, terms in watchlist.items():
        for term in terms:
            pattern = r"\b" + re.escape(term.lower()) + r"\b"
            if re.search(pattern, lowered):
                matches.append((category, term))
    return matches


def match_named(text: str, items: list[dict]) -> list[str]:
    """Case-insensitive whole-term matching against tracked entities or
    campaigns, each {"name": str, "aliases": [str, ...]}. The matched names."""
    lowered = text.lower()
    found: list[str] = []
    for item in items:
        name = item.get("name", "")
        for candidate in [name, *item.get("aliases", [])]:
            if candidate and re.search(r"\b" + re.escape(candidate.lower()) + r"\b", lowered):
                found.append(name)
                break
    return found


def is_high_ticket(cve_mentions: list[tuple[str, float | None]]) -> bool:
    return any(score is not None and score >= HIGH_TICKET_CVSS_THRESHOLD
               for _, score in cve_mentions)


# Real incident wording, not vulnerability-impact wording: "unauthorized
# access to" and "compromised the network" were dropped because hypothetical
# impact sections use them constantly. Weekly roundups can never themselves
# be a breach, so their titles are excluded.
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


# Coverage stating that a PoC or exploit exists or was demonstrated, as
# opposed to abstract exploitability ("could be exploited"). Separate from
# pocs.py, which only sees public GitHub repos. Excluded: negations just
# before the phrase ("no public exploit code"), "proof-of-concept" as a
# maturity stage or a decoy name, and the CVSS "Exploit Code Maturity" field.
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


# Reported real-world exploitation, a different claim from "a PoC exists".
# CISA KEV is authoritative (recorded per CVE by enrich.py) but lags, so this
# catches what coverage itself states. Every branch needs wording that asserts
# real use; conditional framings are removed by the check below.
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

# Conditional framing in the words just before a match: "could be exploited
# in the wild" is a warning, not a report.
_EXPLOITED_NEGATION_RE = re.compile(
    r"\b(no|not|n't|without|could|would|might|may|if|unless|potential(?:ly)?|"
    r"risk of|warns? of|before it is|prevent)\b(?:\s+\w+){0,3}\s*$",
    re.IGNORECASE,
)


# A claim attaches to a CVE named in the same sentence. Scored against CISA
# KEV on 22 September 2026: same sentence 197 CVEs, 74% in KEV (chosen);
# sentence +/-1 211, 73%; a 600-character window 80, 59%.
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def _exploitation_matches(text: str):
    """Every exploitation phrase that survives the conditional check."""
    for m in _EXPLOITED_WILD_RE.finditer(text):
        window_before = text[max(0, m.start() - 40):m.start()]
        if _EXPLOITED_NEGATION_RE.search(window_before):
            continue
        yield m


def exploitation_evidence(title: str, body_text: str) -> tuple[bool, set[str]]:
    """Reported exploitation as (title_claim, cve_ids): the CVEs named in the
    same sentence as an exploitation phrase, and whether the headline itself
    reports exploitation. Per CVE, so a roundup marks only the CVEs it says
    are exploited."""
    text = title + " " + body_text
    title_claim = any(True for _ in _exploitation_matches(title))

    cve_ids: set[str] = set()
    for sentence in _SENTENCE_SPLIT_RE.split(text):
        if any(True for _ in _exploitation_matches(sentence)):
            cve_ids.update(normalize_cve(m.group(0)) for m in CVE_RE.finditer(sentence))
    return title_claim, cve_ids


def exploited_in_wild(title: str, body_text: str) -> bool:
    """The article-level flag; per-CVE detail comes from exploitation_evidence()."""
    title_claim, cve_ids = exploitation_evidence(title, body_text)
    return bool(title_claim or cve_ids)
