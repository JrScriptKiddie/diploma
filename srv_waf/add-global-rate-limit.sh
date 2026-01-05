#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/nginx/conf.d/default.conf"
ZONE_LINE='limit_req_zone $server_name zone=global_limit:10m rate=10r/m;'
LIMIT_LINE='    limit_req zone=global_limit burst=20 nodelay;'

if [[ ! -f "$CONF" ]]; then
  echo "Config not found: $CONF" >&2
  exit 1
fi

# Insert the global zone definition at the top of the file (http context).
if ! grep -qF "$ZONE_LINE" "$CONF"; then
  tmp=$(mktemp)
  printf "%s\n" "$ZONE_LINE" > "$tmp"
  cat "$CONF" >> "$tmp"
  mv "$tmp" "$CONF"
fi

# Add the per-server limit inside the first server block.
if ! grep -qF "$LIMIT_LINE" "$CONF"; then
  tmp=$(mktemp)
  awk -v ins="$LIMIT_LINE" '
    {
      print
      if (!inserted && $0 ~ /^[[:space:]]*server[[:space:]]*\{/){
        print ins
        inserted=1
      }
    }
  ' "$CONF" > "$tmp"
  mv "$tmp" "$CONF"
fi

echo "Global rate limit added to $CONF"
nginx -t && nginx -s reload
