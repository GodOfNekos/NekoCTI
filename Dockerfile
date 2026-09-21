# NekoCTI -- containerized deployment.
#
# Bundles the app, uv (this project's own package manager), Tailscale, and
# the real MITRE ATT&CK STIX bundle, so the whole thing runs under its own
# separate tailnet identity rather than sharing whatever else lives on the
# host machine's own Tailscale node. Same reasoning already applied to TCG
# Price Tracker's container: a hard boundary on what's exposed, not just
# ACLs configured correctly on a personal machine's node.
#
# No Playwright/browser image needed here -- unlike TCG Price Tracker,
# NekoCTI's ingestion (Trafilatura) is plain HTTP, never headless-browser
# scraping, so a slim Python base is enough.
#
# Build:  docker compose build
# Run:    docker compose up -d   (needs TS_AUTHKEY in a .env file -- see
#                                 docker-compose.yml)

FROM python:3.12-slim

# Tailscale via its own apt repo (GPG-signed packages), not curl|sh --
# same discipline already applied in TCG Price Tracker's own Dockerfile.
# `python:3.12-slim` is Debian 13 (trixie), confirmed directly against
# `python:3.12-slim`'s own /etc/os-release (not assumed as bookworm, which
# would be wrong for this base image and 404 the repo below). Version
# 1.102.2 confirmed present in the real trixie repo index before pinning
# to it, matching the version TCG Price Tracker already verified for its
# own (Ubuntu-based) image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg && \
    curl -fsSL https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg \
        -o /usr/share/keyrings/tailscale-archive-keyring.gpg && \
    curl -fsSL https://pkgs.tailscale.com/stable/debian/trixie.tailscale-keyring.list \
        -o /etc/apt/sources.list.d/tailscale.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends tailscale=1.102.2 && \
    rm -rf /var/lib/apt/lists/*

# uv itself, not pip -- this project is uv-managed (pyproject.toml +
# uv.lock, both real and committed) everywhere else in this codebase, so
# the container installs dependencies the same way a real dev environment
# does rather than exporting to a requirements.txt just for Docker's sake.
# Version pinned to match what this machine's own dev environment actually
# runs (`uv --version`), confirmed present on ghcr.io before pinning to it.
COPY --from=ghcr.io/astral-sh/uv:0.12.3 /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY *.py ./
COPY *.json ./
COPY index.html style.css app.js ./
COPY fonts ./fonts
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# The real MITRE ATT&CK STIX bundle -- 51MB of real reference data, not
# source, deliberately never committed to git (see .gitignore's own
# comment) or copied through the Docker build context for the same
# reason. Downloaded fresh at build time from the same real upstream URL
# this project's own README documents for a fresh clone.
RUN curl -sL "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" \
        -o enterprise-attack.json && \
    test -s enterprise-attack.json

# MITRE Center for Threat-Informed Defense's real, human-curated KEV-to-
# ATT&CK mapping -- same reasoning as the STIX bundle above, a real dated
# snapshot (28 July 2025) downloaded fresh at build time, never committed.
# Used by cve_attack.py's "expert" confidence tier.
RUN curl -sL "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json" \
        -o ctid-kev-attack-mapping.json && \
    test -s ctid-kev-attack-mapping.json

# Non-root execution, same reasoning and same pattern as TCG Price
# Tracker's own Dockerfile: --tun=userspace-networking means tailscaled
# never needs NET_ADMIN/a real TUN device, and docker-entrypoint.sh points
# tailscaled's own socket inside the already-owned, already-writable
# /app/data rather than the root-owned default system path.
RUN groupadd --system appuser && \
    useradd --system --gid appuser --home-dir /app --no-create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8778

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
