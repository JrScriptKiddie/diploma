#!/bin/bash
#set -euo pipefail

# Network route
ip route del default 2>/dev/null || true
ip route add default via "${GATEWAY_IP}" || true

echo "Injecting LDAP password into config..."
sed -i "s|LDAP_READONLY_USER_USERNAME|${LDAP_READONLY_USER_USERNAME:-LDAP_READONLY_USER_USERNAME}|g" /etc/nslcd.conf
sed -i "s|LDAP_READONLY_USER_PASSWORD|${LDAP_READONLY_USER_PASSWORD:-LDAP_READONLY_USER_PASSWORD}|g" /etc/nslcd.conf
sed -i "s|IP_LDAP_SRV|${IP_LDAP_SRV:-IP_LDAP_SRV}|g" /etc/nslcd.conf

# Ensure NSS uses LDAP
cat >/etc/nsswitch.conf <<'EOF'
passwd:         files ldap
group:          files ldap
shadow:         files ldap
gshadow:        files
hosts:          files dns
networks:       files
protocols:      db files
services:       db files
ethers:         db files
rpc:            db files
netgroup:       nis
EOF

# Insert pam_ldap in common-* if missing
if ! grep -q pam_ldap /etc/pam.d/common-auth 2>/dev/null; then
  sed -i '1i auth    [success=1 default=ignore] pam_ldap.so use_first_pass' /etc/pam.d/common-auth
fi
if ! grep -q pam_ldap /etc/pam.d/common-account 2>/dev/null; then
  sed -i '1i account sufficient pam_ldap.so' /etc/pam.d/common-account
fi
if ! grep -q pam_ldap /etc/pam.d/common-password 2>/dev/null; then
  sed -i '1i password [success=1 user_unknown=ignore default=die] pam_ldap.so try_first_pass' /etc/pam.d/common-password
fi
if [ -f /etc/pam.d/common-session ] && ! grep -q pam_ldap /etc/pam.d/common-session; then
  sed -i '1i session  optional pam_ldap.so' /etc/pam.d/common-session
fi

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

# Start nslcd directly
mkdir -p /var/run/nslcd && chown nslcd:nslcd /var/run/nslcd
nslcd || echo "nslcd failed to start; check /etc/nslcd.conf"

# rsyslog
/usr/sbin/rsyslogd || true

echo "Testing LDAP connection..."
getent passwd test || echo "LDAP user 'test' not found via NSS"

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
