# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-CVE ATT&CK tags for the POCS tab, in two confidence tiers that are
never blended:

  expert -- MITRE CTID's human-curated KEV-to-ATT&CK mapping
            (center-for-threat-informed-defense/mappings-explorer), with a
            cited source per row. Only KEV entries, so the overlap with
            NekoCTI's archive is small. Applied first, never overridden.
  llm    -- attack.py's local classifier, run on the CVE's own title rather
            than a source article, since a roundup can cover hundreds of
            CVEs. IDs are validated against the STIX catalog the same way.
"""

from __future__ import annotations

import json
from pathlib import Path

import attack
import db

HERE = Path(__file__).resolve().parent
CTID_KEV_MAPPING_PATH = HERE / "ctid-kev-attack-mapping.json"


def apply_expert_mappings(conn) -> int:
    """Apply CTID's mapping to every captured CVE in it that isn't checked
    yet. A static snapshot, so this is cheap to call every run."""
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
    """Validated (technique_id, technique_name) pairs for one CVE's title."""
    if not title.strip():
        return []
    techniques = await attack.classify_article(cve_id, title)
    return [(tid, name) for tid, name, _conf in techniques]
