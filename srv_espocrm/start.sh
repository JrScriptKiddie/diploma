#!/bin/bash

ip route del default
ip route add default via $GATEWAY_IP || true

exec /usr/local/bin/docker-entrypoint.sh apache2-foreground
