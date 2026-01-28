#!/bin/bash

set +e
set -o pipefail

ip route del default
ip route add default via $GATEWAY_IP || true

OPENSEARCH_URL="${ARKIME__elasticsearch:-http://srv_opensearch:9200}"
OPENSEARCH_WAIT_TIMEOUT="${OPENSEARCH_WAIT_TIMEOUT:-300}"
OPENSEARCH_WAIT_INTERVAL="${OPENSEARCH_WAIT_INTERVAL:-2}"

echo "Waiting for OpenSearch at ${OPENSEARCH_URL}..."
SECONDS=0
until curl -sSf "${OPENSEARCH_URL}" >/dev/null 2>&1; do
    if [ "${OPENSEARCH_WAIT_TIMEOUT}" -gt 0 ] && [ "${SECONDS}" -ge "${OPENSEARCH_WAIT_TIMEOUT}" ]; then
        echo "Timed out waiting for OpenSearch after ${OPENSEARCH_WAIT_TIMEOUT}s"
        exit 1
    fi
    sleep "${OPENSEARCH_WAIT_INTERVAL}"
done

echo "OpenSearch is reachable, checking Arkime DB..."

/opt/arkime/db/db.pl "${OPENSEARCH_URL}" init --ifneeded
if [ -n "${ARKIME_ADMIN_PASSWORD}" ]; then
  /opt/arkime/bin/arkime_add_user.sh admin ArkimeAdmin ${ARKIME_ADMIN_PASSWORD} --admin --createOnly
fi

echo "Injecting LDAP password into config..."

# Используем sed для замены.
# Мы используем разделитель | вместо /, чтобы пароль мог содержать слеши.
sed -i "s|LDAP_READONLY_USER_USERNAME|$LDAP_READONLY_USER_USERNAME|g" /etc/nslcd.conf
sed -i "s|LDAP_READONLY_USER_PASSWORD|$LDAP_READONLY_USER_PASSWORD|g" /etc/nslcd.conf
sed -i "s|IP_LDAP_SRV|$IP_LDAP_SRV|g" /etc/nslcd.conf

# Запускаем демон nslcd (клиент LDAP)
service nslcd start
# Выводим диагностику (опционально)
echo "Testing LDAP connection..."
getent passwd test || echo "LDAP user 'test' not found via NSS"

# Enforce pam_access for group-based login control
if ! grep -q '^account required pam_access.so' /etc/pam.d/common-account; then
    echo 'account required pam_access.so' >> /etc/pam.d/common-account
fi

# Create local admin account if needed
if ! id localadmin >/dev/null 2>&1; then
    useradd -m -s /bin/bash localadmin
fi
echo "localadmin:${LOCALADMIN_PASSWORD}" | chpasswd
usermod -aG sudo localadmin

# Access rules: allow root locally, allow bastion admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
+:localadmin:ALL
# Разрешить членам группы ADMINS (имя группы в Linux, не DN!)
+:SG_ADMINS:ALL
# Разрешить членам группы USERS
+:SG_USERS:ALL
# Запретить всем остальным (важно, иначе смысла нет)
-:ALL:ALL
EOF

sed -i "s|SG_USERS|$SG_USERS|g" /etc/security/access.conf
sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/security/access.conf

touch /etc/sudoers.d/ldap-sudo
cat <<'EOF' >> /etc/sudoers.d/ldap-sudo
%SG_ADMINS ALL=(ALL:ALL) ALL
localadmin ALL=(ALL:ALL) ALL
EOF
chown root:root /etc/sudoers.d/ldap-sudo
chmod 0440 /etc/sudoers.d/ldap-sudo
sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/sudoers.d/ldap-sudo

# Запуск rsyslog
/usr/sbin/rsyslogd

# SSH
echo "SSH setup..."
mkdir -p /etc/ssh /run/sshd
chmod 755 /run/sshd
if [ ! -f /etc/ssh/sshd_config ]; then
  cat > /etc/ssh/sshd_config <<'EOF'
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication yes
PermitRootLogin no
UsePAM yes
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
fi
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true
ssh-keygen -A >/dev/null 2>&1 || true
/usr/sbin/sshd

# Передаем управление оригинальному скрипту
echo "Arkime starting..."
exec /opt/arkime/bin/docker.sh capture-viewer --update-geo "$@"
