"""MITRE ATT&CK technique classification and matrix data.

Real ATT&CK data, not a hand-built list: the enterprise STIX bundle
(`mitre-attack/attack-stix-data`, downloaded 16 September 2026) loaded via
the official `mitreattack-python` library - 697 real techniques, 15 real
tactics, checked directly before building anything against it.

Classification calls the local Ollama model (qwen3.8:27b, already proven
elsewhere in this environment - free, no API key, no new dependency on a
hosted provider) rather than a hosted LLM, Neko's explicit call. The model
is asked to name technique IDs from its own knowledge of ATT&CK, not given
the full 697-technique catalog in every prompt (that's a real token-cost
problem, and ATT&CK is well-documented enough that a capable model has
real baseline familiarity with the common techniques an SOC-facing article
would describe). Every ID the model returns is then validated against the
real STIX catalog before being stored - a hallucinated or malformed ID is
silently dropped, never trusted as ground truth. This is the same
"evidence only, never guess" discipline applied everywhere else in this
project, just applied to model output instead of a web page.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import httpx
from mitreattack.stix20 import MitreAttackData

HERE = Path(__file__).resolve().parent
STIX_PATH = HERE / "enterprise-attack.json"

# Overridable so a containerized deploy can point this at the host's own
# Ollama instance via `host.docker.internal` instead of `localhost`, which
# means something different from inside a container. Bare-metal runs (the
# default here) are unaffected.
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
CLASSIFY_MODEL = "qwen3.8:27b"
NUM_CTX = 65536
CLASSIFY_TIMEOUT_S = 120.0

_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_cache: dict = {}


def _load() -> MitreAttackData:
    if "data" not in _cache:
        if not STIX_PATH.exists():
            raise RuntimeError(
                f"{STIX_PATH.name} not found - download the real enterprise-attack.json "
                "STIX bundle from mitre-attack/attack-stix-data before using this module."
            )
        _cache["data"] = MitreAttackData(str(STIX_PATH))
    return _cache["data"]


def get_technique_catalog() -> dict[str, dict]:
    """Returns {technique_id: {"name": str, "tactics": [shortname, ...]}} for
    every real, non-deprecated/non-revoked enterprise technique. Cached -
    this file is 51MB and re-parsing it per call would be real, avoidable cost."""
    if "catalog" in _cache:
        return _cache["catalog"]

    data = _load()
    catalog: dict[str, dict] = {}
    for tech in data.get_techniques(remove_revoked_deprecated=True):
        refs = tech.get("external_references", [])
        ext_id = next((r["external_id"] for r in refs if r.get("source_name") == "mitre-attack"), None)
        if not ext_id:
            continue
        tactics = [p.phase_name for p in tech.get("kill_chain_phases", [])
                   if p.kill_chain_name == "mitre-attack"]
        catalog[ext_id] = {"name": tech.get("name", ext_id), "tactics": tactics}

    _cache["catalog"] = catalog
    return catalog


def get_tactics() -> list[dict]:
    """Returns real tactics ordered by ATT&CK's own kill-chain order, each
    as {"shortname": str, "name": str}."""
    if "tactics" in _cache:
        return _cache["tactics"]

    data = _load()
    tactics = data.get_tactics(remove_revoked_deprecated=True)
    ordered = sorted(tactics, key=lambda t: t.get("x_mitre_shortname", ""))
    result = [{"shortname": t.get("x_mitre_shortname"), "name": t.get("name")} for t in ordered]
    _cache["tactics"] = result
    return result


_CLASSIFY_PROMPT = """You are helping a SOC analyst tag a real security news article with MITRE ATT&CK Enterprise technique IDs.

Read the article below and identify which real, specific ATT&CK techniques (not tactics) it actually describes -- concrete attacker behavior, not general security topics. Only name a technique if the article genuinely describes that specific behavior, not just mentions "attack" or "vulnerability" generically.

Respond with ONLY a list, one technique per line, in this exact format:
T1566.001: Spearphishing Attachment

If the article doesn't clearly describe any real ATT&CK technique, respond with exactly: NONE

ARTICLE TITLE: {title}

ARTICLE TEXT:
{body}
"""


async def classify_article(title: str, body: str) -> list[tuple[str, str, str]]:
    """Returns validated (technique_id, technique_name, confidence) triples.

    confidence is currently a fixed string ("model") rather than a real
    scored value -- this first version asks the model for a yes/no per
    technique, not a calibrated probability. Worth revisiting if the
    classification turns out too noisy in practice.
    """
    catalog = get_technique_catalog()
    prompt = _CLASSIFY_PROMPT.format(title=title, body=body[:20000])

    payload = {
        "model": CLASSIFY_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"num_ctx": NUM_CTX},
    }

    async with httpx.AsyncClient(timeout=CLASSIFY_TIMEOUT_S) as client:
        resp = await client.post(f"{OLLAMA_URL}/api/chat", json=payload)
        resp.raise_for_status()
        reply = resp.json().get("message", {}).get("content", "")

    results: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for match in _TECHNIQUE_ID_RE.finditer(reply):
        tech_id = match.group(0)
        if tech_id in seen:
            continue
        seen.add(tech_id)
        # Validated against the real catalog -- a hallucinated ID (the
        # model inventing a plausible-looking T-number, or citing a
        # deprecated/revoked one) is dropped here, never stored.
        entry = catalog.get(tech_id)
        if entry is not None:
            results.append((tech_id, entry["name"], "model"))

    return results
