#!/bin/bash
set -e

echo "Route changing..."
ip route del default || true
ip route add default via $GATEWAY_IP || true

echo "Go to original entrypoin..."
# Continue with the default OpenLDAP entrypoint from the base image
exec /container/tool/run "$@"
