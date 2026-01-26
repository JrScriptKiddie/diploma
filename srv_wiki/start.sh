#!/bin/sh
set -e

# 1. Меняем маршруты (мы пока root, всё сработает)
echo "Updating routing table..."
ip route del default 2>/dev/null || true
ip route add default via "$GATEWAY_IP" || true

exec /app/leafwiki "$@"