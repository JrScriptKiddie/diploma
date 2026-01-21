#!/bin/sh
set -e

ip route del default || true
ip route add default via $GATEWAY_IP || true

CA_P12="/var/data/certs/proxy_ca.p12"
CA_P12_PASSWORD="${PROXY_CA_P12_PASSWORD:-proxyca}"
CA_ARG=""
if [ -f "$CA_P12" ]; then
  CA_ARG="--cacert load:${CA_P12}:${CA_P12_PASSWORD}"
fi

exec dotnet PolarProxy.dll -v -p "10443, 80, 443" -o "/var/log/PolarProxy/" --leafcert sign --certhttp "10080" $CA_ARG --pcapoveripconnect "$ARKIME_HOST:$ARKIME_PORT" "$@"
