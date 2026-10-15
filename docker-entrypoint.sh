#!/bin/sh
# Copyright (C) 2026 Cameron Gates (GodOfNekos)
# SPDX-License-Identifier: AGPL-3.0-or-later
set -e

mkdir -p /app/data

# The app uses bare relative filenames; symlink each into the mounted volume
# so they survive a rebuild.
for f in nekocti.db watchlist.json tags.json campaigns.json auth.json; do
  [ -e "/app/data/$f" ] || touch "/app/data/$f" 2>/dev/null || true
  ln -sf "/app/data/$f" "/app/$f"
done

# exec: the server becomes the container's main process, so a crash stops the
# container and `restart: unless-stopped` brings it back.
exec /app/.venv/bin/python /app/server.py
