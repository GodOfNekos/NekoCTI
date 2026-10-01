# NekoCTI container: the app, uv, Tailscale (its own tailnet identity, not
# the host's) and the ATT&CK reference data.
#
# Build:  docker compose build
# Run:    docker compose up -d   (needs TS_AUTHKEY in .env for the first join)

FROM python:3.12-slim

# Tailscale from its signed apt repo, not curl|sh. python:3.12-slim is Debian
# 13 (trixie), checked from the image's /etc/os-release; re-check if the base
# tag changes, or the repo URL 404s.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg && \
    curl -fsSL https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg \
        -o /usr/share/keyrings/tailscale-archive-keyring.gpg && \
    curl -fsSL https://pkgs.tailscale.com/stable/debian/trixie.tailscale-keyring.list \
        -o /etc/apt/sources.list.d/tailscale.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends tailscale=1.102.2 && \
    rm -rf /var/lib/apt/lists/*

# uv, pinned to the version the dev machine runs.
COPY --from=ghcr.io/astral-sh/uv:0.12.3 /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY *.py ./
COPY *.json ./
COPY index.html login.html style.css app.js login.js ./
COPY fonts ./fonts
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Reference data, downloaded at build time rather than committed, from pinned
# commits so a build is repeatable. -f makes a 404 fail the build instead of
# saving GitHub's error page. To update, bump the commit.
ARG ATTACK_STIX_COMMIT=6cda5ad8462c79e14fbb872f4e09059b18e0cfc4
ARG CTID_MAPPINGS_COMMIT=ddc842aa48c871cbfc2219cdbb842e9a4e155afe
RUN curl -fsSL "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/${ATTACK_STIX_COMMIT}/enterprise-attack/enterprise-attack.json" \
        -o enterprise-attack.json && \
    curl -fsSL "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/${CTID_MAPPINGS_COMMIT}/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json" \
        -o ctid-kev-attack-mapping.json

# Non-root. Userspace networking means tailscaled needs no TUN device or
# NET_ADMIN, and its socket lives in /app/data (see docker-entrypoint.sh).
RUN groupadd --system appuser && \
    useradd --system --gid appuser --home-dir /app --no-create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8778

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
