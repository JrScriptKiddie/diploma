#!/usr/bin/env bash
#set -euo pipefail

# Defaults
SAMBA_USER=${SAMBA_USER}
SAMBA_PASSWORD=${SAMBA_PASSWORD}
SAMBA_SHARE_PATH=${SAMBA_SHARE_PATH:-/share}

ip route del default || true
ip route add default via $GATEWAY_IP || true

# Configure SSSD from nslcd.conf (mounted)
LDAP_URI=$(awk '$1=="uri"{print $2; exit}' /etc/nslcd.conf || true)
LDAP_BASE=$(awk '$1=="base"{print $2; exit}' /etc/nslcd.conf || true)
LDAP_BINDDN=$(awk '$1=="binddn"{print $2; exit}' /etc/nslcd.conf || true)
LDAP_BINDPW=$(awk '$1=="bindpw"{print $2; exit}' /etc/nslcd.conf || true)

if [[ -z "${LDAP_URI}" || -z "${LDAP_BASE}" || -z "${LDAP_BINDDN}" || -z "${LDAP_BINDPW}" ]]; then
    echo "[srv_fs] Missing LDAP settings in /etc/nslcd.conf"
    exit 1
fi

cat > /etc/sssd/sssd.conf <<EOF
[sssd]
config_file_version = 2
services = nss, pam
domains = LDAP

[nss]
filter_users = root
filter_groups = root

[pam]

[domain/LDAP]
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
ldap_uri = ${LDAP_URI}
ldap_search_base = ${LDAP_BASE}
ldap_default_bind_dn = ${LDAP_BINDDN}
ldap_default_authtok = ${LDAP_BINDPW}
ldap_schema = rfc2307bis
ldap_group_object_class = groupOfNames
ldap_group_member = member
ldap_group_nesting_level = 2
ldap_tls_reqcert = never
ldap_id_use_start_tls = False
ldap_referrals = False
cache_credentials = True
enumerate = True
entry_cache_timeout = 60
entry_cache_user_timeout = 60
entry_cache_group_timeout = 60
entry_cache_negative_timeout = 60


EOF

chmod 600 /etc/sssd/sssd.conf
mkdir -p /var/lib/sss/db /var/log/sssd

/usr/sbin/sssd

echo "Testing LDAP connection via SSSD..."
getent passwd test || echo "LDAP user 'test' not found via NSS"
getent group SG-RES-SHARE-RW || echo "LDAP group 'SG-RES-SHARE-RW' not found via NSS"

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

# SSH
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

# Запуск rsyslog
/usr/sbin/rsyslogd

# WAZUH AGENT START
#/var/ossec/bin/wazuh-control start

## SAMBA
# Create local users (system + ansible)
if ! id -u "$SAMBA_USER" >/dev/null 2>&1; then
   echo "Creating $SAMBA_USER:$SAMBA_PASSWORD"
  useradd -m -s /bin/bash "$SAMBA_USER" || true
fi
echo "$SAMBA_USER:$SAMBA_PASSWORD" | chpasswd
echo "$SAMBA_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/90-$SAMBA_USER
chmod 0440 /etc/sudoers.d/90-$SAMBA_USER

mkdir -p "$SAMBA_SHARE_PATH"
chmod -R 0777 "$SAMBA_SHARE_PATH" || true

# Samba configuration
mkdir -p /var/log/samba

# Create Samba user (requires system account to exist)
printf '%s\n%s\n' "$SAMBA_PASSWORD" "$SAMBA_PASSWORD" | smbpasswd -s -a "$SAMBA_USER" || true

mkdir -p /var/log/supervisor
cat <<'EOF' > /etc/supervisor/conf.d/samba.conf
[program:nmbd]
command=/usr/sbin/nmbd -F --no-process-group
autorestart=true
stdout_logfile=/var/log/supervisor/nmbd.log
stderr_logfile=/var/log/supervisor/nmbd.log
priority=10

[program:smbd]
command=/usr/sbin/smbd -F --no-process-group
autorestart=true
stdout_logfile=/var/log/supervisor/smbd.log
stderr_logfile=/var/log/supervisor/smbd.log
priority=20

[program:wazuh-start]
command=/var/ossec/bin/wazuh-control start
autostart=true
autorestart=false
startretries=0
exitcodes=0
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
stdout_logfile_backups=0
priority=30
EOF

exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
