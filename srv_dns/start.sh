#!/bin/sh
set -eu

ip route del default 2>/dev/null || true
ip route add default via "$GATEWAY_IP" || true

exec coredns -conf /etc/coredns/Corefile
