# NekoCTI

A self-hosted OSINT/threat-intelligence dashboard. Ingests security news (The Hacker News, CISA
KEV), extracts CVE/CVSS data, filters against a vendor watchlist, flags major breaches, tracks
named threat actors/APT groups over time, and maps captured intel against the real MITRE ATT&CK
framework.

Full plan, phasing, design decisions, and build history live in the vault: `14 - NekoCTI/NekoCTI.md`.

## Status

Real Phase 1 pipeline and web dashboard both built and live-verified, 16 September 2026. Pip-Boy
Personal Monitor direction, verified against a real Fallout 4 Pip-Boy recreation before building
(see the vault note's Brand Commitments section for the specifics). Still open: Impeccable's own
finish-review pass (screenshot inspection, the design-detector scan, `DESIGN.md`) hasn't run yet.

## Stack

- `uv`-managed Python project, matching every other tool in this codebase.
- `feedparser` - RSS ingestion.
- `trafilatura` - full-article extraction (benchmarked against newspaper4k/boilerpy3 - see the
  vault note for the research).
- `mitreattack-python` - real MITRE ATT&CK technique/tactic data, not a hand-built list.
- SQLite for the local archive (`nekocti.db`, gitignored - real accumulated data, not source).
- Backend: Python stdlib `http.server`, no framework - binds to `127.0.0.1` only.
- Frontend: plain HTML/CSS/vanilla JS, no build step.

## One real setup step

The MITRE ATT&CK STIX bundle (`enterprise-attack.json`, ~51MB, gitignored) isn't committed. Before
running `classify` or opening the ATT&CK tab on a fresh clone:

```
curl -sL "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" -o enterprise-attack.json
```

## Config

- `watchlist.json` - vendor/product relevance list. Tags items as relevant without discarding
  anything else. Fully editable from the dashboard's WATCHLIST tab too (the "MANAGE WATCHLIST" toggle).
- `tags.json` - named threat-actor/campaign/malware-family tracking list, with aliases. Editable
  from the dashboard's APT/ENTITIES tab.

## Running

```
uv run python main.py ingest             # poll all sources once
uv run python main.py classify           # real MITRE ATT&CK classification (local Ollama, qwen3.8:27b)
uv run python main.py digest             # build a grouped digest, write it to the vault daily note
uv run python server.py                  # start the dashboard at http://127.0.0.1:8778/
```

Classification calls the local Ollama model already running on this machine - no API key, no
hosted-provider cost. Every technique ID the model returns is validated against the real STIX
catalog before being stored; a hallucinated ID is silently dropped, never trusted.
