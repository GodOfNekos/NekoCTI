"""Real per-CVE MITRE ATT&CK technique tagging for the POCS tab, Neko's
explicit request: tag every CVE with real PoC evidence against ATT&CK
"where possible" - built as two honestly separate confidence tiers, never
blended, the same honesty already used for "confirmed repo" vs "mention
only" elsewhere in this tab.

Tier 1, "expert": MITRE's own Center for Threat-Informed Defense publishes
a real, human-curated CVE-to-ATT&CK mapping
(github.com/center-for-threat-informed-defense/mappings-explorer),
covering exploitation technique plus primary/secondary impact per CVE,
each with a real cited source. Checked directly, 17 September 2026: scoped
only to CISA KEV entries, snapshot dated 28 July 2025 (419 distinct CVEs
total, nothing from 2026) - real overlap against NekoCTI's full captured
archive (4,118 CVEs) is 36. Small, but the highest-confidence tag
available, so applied first and never overridden by the fallback below.

Tier 2, "llm": for every other real CVE with PoC evidence, NekoCTI's own
local Ollama classifier (attack.py, already proven against whole articles)
runs against that CVE's own narrow title/description text - not the
source article, which can cover hundreds of CVEs at once and would
reintroduce the exact over-attribution problem already found and fixed
once in this tab (see NekoCTI.md, 16 September 2026). Same validation
discipline as attack.py: every technique ID is checked against the real
STIX catalog before being stored, a hallucinated ID is dropped.
"""

from __future__ import annotations

import json
from pathlib import Path

import attack
import db

HERE = Path(__file__).resolve().parent
CTID_KEV_MAPPING_PATH = HERE / "ctid-kev-attack-mapping.json"


def apply_expert_mappings(conn) -> int:
    """Loads MITRE CTID's real KEV-to-ATT&CK mapping and applies it to
    every real CVE NekoCTI has already captured that appears in it. A
    static dataset (CTID's own dated snapshot, not a live feed), so this
    is safe and cheap to call every run - a CVE already marked checked is
    skipped outright, no re-parsing of its own rows."""
    if not CTID_KEV_MAPPING_PATH.exists():
        return 0

    data = json.loads(CTID_KEV_MAPPING_PATH.read_text(encoding="utf-8"))
    captured = db.get_all_captured_cve_ids(conn)
    already_checked = db.get_checked_attack_cve_ids(conn)

    by_cve: dict[str, list[dict]] = {}
    for obj in data.get("mapping_objects", []):
        cve_id = obj.get("capability_id")
        if cve_id in captured and cve_id not in already_checked:
            by_cve.setdefault(cve_id, []).append(obj)

    for cve_id, objs in by_cve.items():
        rows = []
        for obj in objs:
            tech_id = obj.get("attack_object_id")
            tech_name = obj.get("attack_object_name")
            if not (tech_id and tech_name):
                continue
            refs = obj.get("references") or []
            rows.append((
                tech_id, tech_name, "expert", obj.get("mapping_type"),
                obj.get("comments"), refs[0] if refs else None,
            ))
        if rows:
            db.insert_cve_attack_techniques(conn, cve_id, rows)
        db.mark_cve_attack_checked(conn, cve_id)

    return len(by_cve)


async def classify_cve_llm(cve_id: str, title: str) -> list[tuple[str, str]]:
    """Runs the existing article classifier against just this CVE's own
    narrow title/description text, deliberately not the source article -
    a roundup article's classification can't be trusted to describe any
    one of the hundreds of CVEs it might list. Returns validated
    (technique_id, technique_name) pairs, confidence already implied by
    the caller storing them as tier "llm"."""
    if not title.strip():
        return []
    techniques = await attack.classify_article(cve_id, title)
    return [(tid, name) for tid, name, _conf in techniques]
