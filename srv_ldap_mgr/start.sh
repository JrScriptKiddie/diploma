#!/usr/bin/env bash
set -euo pipefail

# Default route via firewall
ip route del default || true
ip route add default via "${GATEWAY_IP}" || true

# NSLCD config access (if mounted)
if [ -f /etc/nslcd.conf ]; then
  chown root:nslcd /etc/nslcd.conf && chmod 640 /etc/nslcd.conf
fi

# Enforce pam_access for group-based login control
if ! grep -q '^account required pam_access.so' /etc/pam.d/common-account; then
  echo 'account required pam_access.so' >> /etc/pam.d/common-account
fi

: "${SG_ADMINS:=SG-ADMINS}"

# Create local admin account if needed
if ! id localadmin >/dev/null 2>&1; then
  useradd -u 6666 -m -s /bin/bash localadmin
fi
echo "localadmin:${LOCALADMIN_PASSWORD}" | chpasswd
usermod -aG sudo localadmin

# Access rules: allow root locally, allow admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
+:localadmin:ALL
# Разрешить членам группы ADMINS (имя группы в Linux, не DN!)
+:SG_ADMINS:ALL
+:ansible:ALL
# Запретить всем остальным
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

# Start LDAP client
if command -v nslcd >/dev/null 2>&1; then
  nslcd
fi

# Run SSH server
mkdir -p /run/sshd
chmod 755 /run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
/usr/sbin/sshd

# WAZUH AGENT START
/var/ossec/bin/wazuh-control start

echo "Go to original entrypoin..."
# Continue with the default OpenLDAP entrypoint from the base image
exec /container/tool/run "$@"
