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
uv run python main.py enrich             # per-CVE severity and exploitation facts (see below)
uv run python server.py                  # start the dashboard at http://127.0.0.1:8778/
```

Classification calls the local Ollama model already running on this machine - no API key, no
hosted-provider cost. Every technique ID the model returns is validated against the real STIX
catalog before being stored; a hallucinated ID is silently dropped, never trusted.

## CVE enrichment (`enrich`)

Fills in what the coverage itself rarely states, for CVEs already captured.
Four separate signals, kept apart on purpose because they answer different
questions:

| Signal | Source | Means |
|---|---|---|
| Severity | NVD 2.0 | The official CVSS base score, severity, vector and CWE. Most captured CVEs have no score otherwise: only those whose article text happened to quote one. |
| Exploited (confirmed) | CISA KEV | It is being exploited in the wild, per CISA, with the date added and whether it is used in ransomware. |
| Exploited (reported) | our own captured articles | Coverage states this CVE is being exploited, which often lands days before a KEV entry. A CVE named in the same sentence as an exploitation phrase. |
| Exploitation likelihood | FIRST.org EPSS | Predicted probability of exploitation in the next 30 days, and its percentile. Refreshed daily. |

A public PoC (`classify-pocs`, `pocs.py`) is a fifth and different thing:
exploit code exists, which says nothing about whether anyone is using it.

```
uv run python main.py enrich                 # everything, 200 NVD lookups max
uv run python main.py enrich --limit 4000    # a full NVD backfill
uv run python main.py enrich --no-nvd        # EPSS + KEV + reporting only (fast)
uv run python main.py enrich --no-backfill   # skip re-scanning stored articles
```

**NVD is rate-limited**: 5 requests per rolling 30 seconds without an API
key, 50 with one, and it is one request per CVE. Set `NVD_API_KEY` (free,
from NVD) to make a full backfill take about 90 minutes instead of about 7
hours. Everything works without it, just slower, and each run is bounded by
`--limit` with CVEs ordered by triage priority: high ticket first, then
watchlist matches, then anything with no severity, newest first.

EPSS is batched and cheap (roughly 40 requests for 4,000 CVEs), and the KEV
catalog is a single request, so `--no-nvd` gives a complete refresh of both
in seconds.

An article is promoted to **high ticket** when it reports exploitation, or
mentions a CVE that is KEV-listed, scores 9.0+ at NVD, or sits at or above
the 95th EPSS percentile. Promotion only ever adds the flag.

### Freshness

Every check (the dashboard's **Run check now**, or `main.py ingest`) ends with
a refresh pass, so a run re-verifies facts as well as fetching articles:
EPSS, the KEV catalog, exploitation reporting on the new text, and up to 40
NVD lookups so CVEs that just arrived get a severity. It costs about two
seconds when everything is already current, and a failure there is reported
separately rather than losing a successful ingest.

The dashboard footer shows when each lookup last ran, how many CVEs carry a
severity and how many are still waiting. An EPSS score older than two days
is marked `STALE` next to its percentile rather than being hidden; the next
check refreshes it.

Nothing is ever deleted for age. The archive is around 27MB, old coverage is
still evidence, and a retention rule measured against the real library would
have removed 63% of it along with every article referencing 3,245 CVEs.
