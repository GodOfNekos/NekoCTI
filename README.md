# NekoCTI

A self-hosted OSINT and threat-intelligence dashboard for one analyst. It pulls new vulnerability
disclosures and threat-intel coverage from 34 sources into one place, extracts CVEs and scores,
filters them against your vendor watchlist, tracks named threat actors and campaigns over time,
enriches every CVE with severity and exploitation facts, and maps coverage onto MITRE ATT&CK.

Written by Cameron Gates (GodOfNekos). Free software under the GNU Affero General Public License v3.0 or later
(see [Licence](#licence)).

## What it does

- **Sources:** The Hacker News and Krebs on Security (RSS), CISA KEV, GitHub Security Advisories,
  and 30 curated threat-intel blogs (analyst, community, government, vendor and media).
- **Dashboard tabs:** HIGH TICKET, WATCHLIST, BREACHES, APT / ENTITIES, CAMPAIGNS, ARCHIVE,
  ATT&CK and POCS. Built for daily use on desktop, tablet and phone.
- **CVE enrichment,** four signals kept apart on purpose:

  | Signal | Source | Means |
  |---|---|---|
  | Severity | NVD 2.0 | The official CVSS base score, severity, vector and CWE. |
  | Exploited (confirmed) | CISA KEV | Exploited in the wild, per CISA, with the date added and ransomware use. |
  | Exploited (reported) | captured coverage | An article states the CVE is being exploited, often days before KEV lists it. |
  | Likelihood | FIRST.org EPSS | Predicted probability of exploitation in the next 30 days. |

  A public proof-of-concept is a fifth, separate fact: exploit code exists, which says nothing
  about use.
- **High ticket:** anything at CVSS 9.0+, KEV-listed, reported exploited, at or above the 95th
  EPSS percentile, or a critical GitHub advisory, whatever the vendor.
- **ATT&CK mapping** by a local LLM through [Ollama](https://ollama.com). Every technique ID it
  returns is checked against the real ATT&CK catalogue, and anything invented is dropped.
- **Nothing is deleted for age.** Every check re-verifies the facts instead (EPSS, KEV,
  exploitation reporting and new severities), and the footer shows how current they are.
- **Optional daily digest:** a one-line-per-article summary appended to a Markdown daily note.

## Stack

Python 3.12 managed by [uv](https://docs.astral.sh/uv/), the standard library's `http.server`
for the dashboard, plain HTML, CSS and JavaScript with no build step, and SQLite for storage.
Dependencies: `feedparser`, `httpx`, `trafilatura` and `mitreattack-python`.

## Running it

### Docker (how it's meant to run)

The container joins your [Tailscale](https://tailscale.com) network as its own device and serves
the dashboard over HTTPS with `tailscale serve`. It publishes no port on the host.

1. Copy `.env.example` to `.env` and set `TS_AUTHKEY` (a Tailscale auth key). `NVD_API_KEY` is
   optional and makes NVD lookups ten times faster.
2. Optional: to receive the digest, set `DIGEST_NOTES_DIR` to the folder holding your daily notes
   (`YYYY-MM-DD.md` files). Otherwise it goes to `./digest-notes`.
3. `docker compose up -d --build`
4. Set the dashboard password: `docker compose exec nekocti /app/.venv/bin/python main.py set-password`
5. Open `https://<TS_HOSTNAME>.<your-tailnet>.ts.net/` from a device on your tailnet.

ATT&CK classification needs Ollama on the Docker host (`OLLAMA_URL`, default
`http://host.docker.internal:11434`) with the model named in `attack.py`.

### Locally

```
uv sync
curl -fsSL "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" -o enterprise-attack.json
uv run python main.py set-password
uv run python server.py                  # dashboard at http://127.0.0.1:8778/
```

### Commands

```
uv run python main.py ingest             # poll every source once (the dashboard's RUN CHECK NOW does the same)
uv run python main.py classify           # ATT&CK classification with the local LLM
uv run python main.py enrich             # CVE severity and exploitation facts (--limit, --no-nvd)
uv run python main.py digest --no-write  # print the digest (without --no-write it appends to today's note)
```

There's no scheduler on purpose: a check runs when you press the button or call `ingest`.

## Configuration

- `watchlist.json`: vendors and products you care about. Matching tags items, never hides others.
- `tags.json` and `campaigns.json`: named threat actors and campaigns to track, with aliases.

All three are editable from the dashboard and live in `data/` under Docker.

## Security

- **Keep it off the public internet.** It's built to sit on a private network (Tailscale here)
  behind its own password login, with 30-day sessions.
- Feed content is untrusted. Everything is escaped before display, links and images are
  http(s)-only, a strict Content-Security-Policy is set, and article pages are fetched only from
  public addresses. Writes need a custom header, and config writes are validated and capped.
- Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Licence

Copyright (C) 2026 Cameron Gates (GodOfNekos).

NekoCTI is free software: you can redistribute it and/or modify it under the terms of the GNU
Affero General Public License as published by the Free Software Foundation, either version 3 of
the License, or (at your option) any later version. It is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See [LICENSE](LICENSE) for the full text.

If you run a modified version for other people over a network, the AGPL requires you to offer
them your version's source code. The dashboard and login page link to the source for this reason.

Third-party data, code and fonts are credited in [NOTICE.md](NOTICE.md).
