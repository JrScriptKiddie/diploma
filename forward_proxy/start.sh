#!/bin/sh
set -e

ip route del default || true
ip route add default via $GATEWAY_IP || true

# NSLCD config access
chown root:nslcd /etc/nslcd.conf && chmod 640 /etc/nslcd.conf

# Enforce pam_access for group-based login control
if ! grep -q '^account required pam_access.so' /etc/pam.d/common-account; then
    echo 'account required pam_access.so' >> /etc/pam.d/common-account
fi

# Create local admin account if needed
if ! id localadmin >/dev/null 2>&1; then
    useradd -u 6666 -m -s /bin/bash localadmin
fi
echo "localadmin:${LOCALADMIN_PASSWORD}" | chpasswd
usermod -aG sudo localadmin

# Access rules: allow root locally, allow bastion admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
+:localadmin:ALL
# Разрешить членам группы ADMINS (имя группы в Linux, не DN!)
+:SG_ADMINS:ALL
# Запретить всем остальным (важно, иначе смысла нет)
-:ALL:ALL
EOF

sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/security/access.conf

touch /etc/sudoers.d/ldap-sudo
cat <<'EOF' >> /etc/sudoers.d/ldap-sudo
%SG_ADMINS ALL=(ALL:ALL) ALL
localadmin ALL=(ALL:ALL) ALL
EOF
chown root:root /etc/sudoers.d/ldap-sudo
chmod 0440 /etc/sudoers.d/ldap-sudo
sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/sudoers.d/ldap-sudo

# Запускаем демон nslcd (клиент LDAP) без OpenRC
if command -v nslcd >/dev/null 2>&1; then
    nslcd
else
    echo "[fw] nslcd not found, skipping"
fi

# Запуск rsyslog
/usr/sbin/rsyslogd

# Выводим диагностику (опционально)
echo "Testing LDAP connection..."
getent passwd test || echo "LDAP user 'test' not found via NSS"

# Run SSH server
mkdir -p /run/sshd
chmod 755 /run/sshd
/usr/sbin/sshd

# WAZUH AGENT START
/var/ossec/bin/wazuh-control start

CA_P12="/var/data/certs/proxy_ca.p12"
CA_P12_PASSWORD="${PROXY_CA_P12_PASSWORD:-proxyca}"
CA_ARG=""
if [ -f "$CA_P12" ]; then
  CA_ARG="--cacert load:${CA_P12}:${CA_P12_PASSWORD}"
fi

exec dotnet PolarProxy.dll -v -p "10443, 80, 443" -o "/var/log/PolarProxy/" --leafcert sign --certhttp "10080" $CA_ARG --pcapoveripconnect "$ARKIME_HOST:$ARKIME_PORT" "$@"
