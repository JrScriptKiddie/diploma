#!/bin/bash

ip route del default || true
ip route add default via "$GATEWAY_IP" || true

# Create local admin user with sudo and password auth (admin / Qwerty!2)
if ! id "$WG_PORTAL_ADMIN_USERТNAME" >/dev/null 2>&1; then
    adduser -D -h /home/"$WG_PORTAL_ADMIN_PASSWORD" -s /bin/sh "$WG_PORTAL_ADMIN_USERNAME"
    echo "${WG_PORTAL_ADMIN_USERNAME}:${WG_PORTAL_ADMIN_PASSWORD}" | chpasswd
    addgroup "$WG_PORTAL_ADMIN_USERNAME" wheel
fi
echo "%wheel ALL=(ALL:ALL) ALL" >/etc/sudoers.d/wheel
chmod 0440 /etc/sudoers.d/wheel

sed -i "s|WG_PORTAL_ADMIN_USERТNAME|$WG_PORTAL_ADMIN_USERТNAME|g" /app/config/config.yaml
sed -i "s|WG_PORTAL_ADMIN_PASSWORD|$WG_PORTAL_ADMIN_PASSWORD|g" /app/config/config.yaml

# Configure and start SSH daemon with password auth enabled
mkdir -p /run/sshd
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
ssh-keygen -A
/usr/sbin/sshd

# Start rsyslog
# Disable imklog (not available in containers)
if [ -f /etc/rsyslog.conf ]; then
    sed -i '/^[^#]*imklog/s/^/#/' /etc/rsyslog.conf
fi
/usr/sbin/rsyslogd

exec /app/wg-portal "$@"
