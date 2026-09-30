#!/bin/sh
set -e

mkdir -p /app/data

# The app uses bare relative filenames; symlink each into the mounted volume
# so they survive a rebuild.
for f in nekocti.db watchlist.json tags.json campaigns.json; do
  [ -e "/app/data/$f" ] || touch "/app/data/$f" 2>/dev/null || true
  ln -sf "/app/data/$f" "/app/$f"
done

# Userspace networking: no TUN device or NET_ADMIN needed. --statedir because
# serve's HTTPS needs a directory for certificates; the socket lives in
# /app/data because the default path is root-owned.
TS_STATE_DIR=/app/data/tailscale-state
TS_SOCKET=$TS_STATE_DIR/tailscaled.sock

tailscaled --tun=userspace-networking --statedir="$TS_STATE_DIR" --socket="$TS_SOCKET" &
TAILSCALED_PID=$!

for i in $(seq 1 30); do
  [ -S "$TS_SOCKET" ] && break
  sleep 1
done

# The auth key is only needed to join the first time. With saved state the
# node reconnects on its own identity, so the key can expire or be removed.
if [ -s "$TS_STATE_DIR/tailscaled.state" ]; then
  tailscale --socket="$TS_SOCKET" up --hostname="${TS_HOSTNAME:-nekocti}"
else
  if [ -z "$TS_AUTHKEY" ]; then
    echo "No saved Tailscale state and TS_AUTHKEY is not set -- this container can't join the tailnet." >&2
    echo "Generate an auth key at https://login.tailscale.com/admin/settings/keys" >&2
    exit 1
  fi
  tailscale --socket="$TS_SOCKET" up --authkey="$TS_AUTHKEY" --hostname="${TS_HOSTNAME:-nekocti}"
fi

# Tailnet only: never `tailscale funnel`, which would make it public.
tailscale --socket="$TS_SOCKET" serve --bg 8778

# Both processes run in the background and are polled, so either one dying
# stops the container and `restart: unless-stopped` recovers it.
/app/.venv/bin/python /app/server.py &
APP_PID=$!

while true; do
  if ! kill -0 "$TAILSCALED_PID" 2>/dev/null; then
    echo "tailscaled (pid $TAILSCALED_PID) died -- stopping the container so restart: unless-stopped can recover it." >&2
    kill "$APP_PID" 2>/dev/null || true
    exit 1
  fi
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    echo "server.py (pid $APP_PID) exited -- stopping the container." >&2
    kill "$TAILSCALED_PID" 2>/dev/null || true
    exit 1
  fi
  sleep 5
done
