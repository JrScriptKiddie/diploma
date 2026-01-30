#!/bin/bash
set -e

echo "Route changing..."
ip route del default || true
ip route add default via $GATEWAY_IP || true

echo 'local4.* /var/log/slapd.log' > /etc/rsyslog.d/slapd.conf
/usr/sbin/rsyslogd

echo "Wazuh installing..."
chmod +x /opt/wazuh_agent.sh
./opt/wazuh_agent.sh

touch /usr/bin/.rootkit
chmod 777 /usr/bin/.rootkit

echo "Go to original entrypoin..."
# Continue with the default OpenLDAP entrypoint from the base image
exec /container/tool/run "$@"
