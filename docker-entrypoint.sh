#!/bin/sh
set -e

mkdir -p /app/data

# db.py/extract.py all use bare relative filenames (nekocti.db,
# watchlist.json, tags.json, campaigns.json) resolved against the
# project's own directory -- true on bare-metal too. Symlinking each into
# the mounted volume means every one of them survives a container rebuild
# without touching that existing path logic at all. Same pattern TCG Price
# Tracker's own entrypoint already uses for its CSV/DB files.
for f in nekocti.db watchlist.json tags.json campaigns.json; do
  [ -e "/app/data/$f" ] || touch "/app/data/$f" 2>/dev/null || true
  ln -sf "/app/data/$f" "/app/$f"
done

# Userspace networking mode: no TUN device, no NET_ADMIN capability needed
# on the container. This node's only job is serving one app over the
# tailnet via `tailscale serve` -- same reasoning as TCG Price Tracker's
# own entrypoint, which this is deliberately modeled on.
#
# --statedir, not --state (see TCG Price Tracker's entrypoint for the full
# real reasoning already found there: `tailscale serve`'s HTTPS needs a
# real *directory* for TLS cert storage, not a single state file).
# Socket pointed inside /app/data for the same non-root-ownership reason
# already established there too.
TS_SOCKET=/app/data/tailscale-state/tailscaled.sock

tailscaled --tun=userspace-networking --socks5-server=localhost:1055 \
  --statedir=/app/data/tailscale-state --socket="$TS_SOCKET" &
TAILSCALED_PID=$!

for i in $(seq 1 30); do
  [ -S "$TS_SOCKET" ] && break
  sleep 1
done

if [ -z "$TS_AUTHKEY" ]; then
  echo "TS_AUTHKEY is not set -- this container can't join the tailnet." >&2
  echo "Generate a reusable auth key at https://login.tailscale.com/admin/settings/keys" >&2
  exit 1
fi

tailscale --socket="$TS_SOCKET" up --authkey="$TS_AUTHKEY" --hostname="${TS_HOSTNAME:-nekocti}"

# Private within the tailnet only -- never `tailscale funnel`, which would
# put this on the public internet. Same "never a public port" reasoning
# already used for TCG Price Tracker and ZAX Mobile & Web Access.
tailscale --socket="$TS_SOCKET" serve --bg 8778

# Not `exec uv run ...` -- same reasoning as TCG Price Tracker's own
# entrypoint: exec would replace this shell with the app process, leaving
# nothing watching whether tailscaled (backgrounded above) was still
# alive. Running the app backgrounded too and polling both PIDs means
# either one dying stops the whole container, so `restart: unless-stopped`
# can actually do its job.
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
