#!/bin/bash
#set -euo pipefail

# Network route
ip route del default 2>/dev/null || true
ip route add default via "${GATEWAY_IP}" || true

# SSSD execute and test
mkdir -p /etc/sssd
cp /etc/sssd_temp.conf /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
mkdir -p /var/lib/sss/db /var/log/sssd
/usr/sbin/sssd
echo "Testing LDAP connection via SSSD..."
while true; do
    if getent passwd test >/dev/null 2>&1; then
        echo "LDAP connection OK, NSS cache warmed."
        break
    else
        echo "LDAP user 'test' not found via NSS"
    fi
    sleep 2
done
# Enforce pam_access for group-based login control
if ! grep -q '^account required pam_access.so' /etc/pam.d/common-account 2>/dev/null; then
    echo 'account required pam_access.so' >> /etc/pam.d/common-account
fi

# Access rules: allow root locally, allow bastion admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
+:SG_ADMINS:ALL
-:ALL:ALL
EOF
sed -i "s|SG_ADMINS|${SG_ADMINS:-SG_ADMINS}|g" /etc/security/access.conf

touch /etc/sudoers.d/ldap-sudo
cat <<'EOF' > /etc/sudoers.d/ldap-sudo
%SG_ADMINS ALL=(ALL:ALL) ALL
EOF
sed -i "s|SG_ADMINS|${SG_ADMINS:-SG_ADMINS}|g" /etc/sudoers.d/ldap-sudo
chmod 0440 /etc/sudoers.d/ldap-sudo

# rsyslog
/usr/sbin/rsyslogd || true
# SSH setup
mkdir -p /etc/ssh /run/sshd
if ! ls /etc/ssh/ssh_host_* >/dev/null 2>&1; then
  ssh-keygen -A
fi
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
if grep -q '/usr/lib/openssh/sftp-server' /etc/ssh/sshd_config && [ -x /usr/lib/ssh/sftp-server ]; then
  sed -i 's|/usr/lib/openssh/sftp-server|/usr/lib/ssh/sftp-server|' /etc/ssh/sshd_config
fi
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true
/usr/sbin/sshd || { echo "sshd failed to start (check host keys)"; exit 1; }

# Cleanup default site if present
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default 2>/dev/null || true
rm -f /etc/nginx/http.d/default.conf 2>/dev/null || true

# Start nginx in foreground
nginx -g 'daemon off;'



